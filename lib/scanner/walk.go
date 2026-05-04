// Copyright (C) 2014 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	metrics "github.com/rcrowley/go-metrics"
	"golang.org/x/text/unicode/norm"

	"github.com/syncthing/syncthing/internal/slogutil"
	"github.com/syncthing/syncthing/lib/build"
	"github.com/syncthing/syncthing/lib/events"
	"github.com/syncthing/syncthing/lib/fs"
	"github.com/syncthing/syncthing/lib/ignore"
	"github.com/syncthing/syncthing/lib/osutil"
	"github.com/syncthing/syncthing/lib/protocol"
)

type Config struct {
	// Folder for which the walker has been created
	Folder string
	// Limit walking to these paths within Dir, or no limit if Sub is empty
	Subs []string
	// If Matcher is not nil, it is used to identify files to ignore which were specified by the user.
	Matcher *ignore.Matcher
	// Number of hours to keep temporary files for
	TempLifetime time.Duration
	// If CurrentFiler is not nil, it is queried for the current file before rescanning.
	CurrentFiler CurrentFiler
	// The Filesystem provides an abstraction on top of the actual filesystem.
	Filesystem fs.Filesystem
	// If IgnorePerms is true, changes to permission bits will not be
	// detected.
	IgnorePerms bool
	// When AutoNormalize is set, file names that are in UTF8 but incorrect
	// normalization form will be corrected.
	AutoNormalize bool
	// Number of routines to use for hashing
	Hashers int
	// Our vector clock id
	ShortID protocol.ShortID
	// Optional progress tick interval which defines how often FolderScanProgress
	// events are emitted. Negative number means disabled.
	ProgressTickIntervalS int
	// Local flags to set on scanned files
	LocalFlags protocol.FlagLocal
	// Modification time is to be considered unchanged if the difference is lower.
	ModTimeWindow time.Duration
	// Event logger to which the scan progress events are sent
	EventLogger events.Logger
	// If ScanOwnership is true, we pick up ownership information on files while scanning.
	ScanOwnership bool
	// If ScanXattrs is true, we pick up extended attributes on files while scanning.
	ScanXattrs bool
	// Filter for extended attributes
	XattrFilter XattrFilter
	// Number of directory traversal workers. Zero or negative means default.
	Walkers int
}

type CurrentFiler interface {
	// CurrentFile returns the file as seen at last scan.
	CurrentFile(name string) (protocol.FileInfo, bool)
}

type XattrFilter interface {
	Permit(string) bool
	GetMaxSingleEntrySize() int
	GetMaxTotalSize() int
}

type ScanResult struct {
	File protocol.FileInfo
	Err  error
	Path string // to be set in case Err != nil and File == nil
}

func Walk(ctx context.Context, cfg Config) chan ScanResult {
	return newWalker(cfg).walk(ctx)
}

func WalkWithoutHashing(ctx context.Context, cfg Config) chan ScanResult {
	return newWalker(cfg).walkWithoutHashing(ctx)
}

func newWalker(cfg Config) *walker {
	w := &walker{cfg}

	if w.CurrentFiler == nil {
		w.CurrentFiler = noCurrentFiler{}
	}
	if w.Filesystem == nil {
		panic("no filesystem specified")
	}
	if w.Matcher == nil {
		w.Matcher = ignore.New(w.Filesystem)
	}

	registerFolderMetrics(w.Folder)
	return w
}

var (
	errUTF8Invalid       = errors.New("item is not in UTF8 encoding")
	errUTF8Normalization = errors.New("item is not in the correct UTF8 normalization form")
	errUTF8Conflict      = errors.New("item has UTF8 encoding conflict with another item")
)

type walker struct {
	Config
}

// Walk returns the list of files found in the local folder by scanning the
// file system. Files are blockwise hashed.
func (w *walker) walk(ctx context.Context) chan ScanResult {
	l.Debugln(w, "Walk", w.Subs, w.Matcher)

	toHashChan := make(chan protocol.FileInfo)
	finishedChan := make(chan ScanResult)

	// A routine which walks the filesystem tree, and sends files which have
	// been modified to the counter routine.
	go w.scan(ctx, toHashChan, finishedChan)

	// We're not required to emit scan progress events, just kick off hashers,
	// and feed inputs directly from the walker.
	if w.ProgressTickIntervalS < 0 {
		newParallelHasher(ctx, w.Folder, w.Filesystem, w.Hashers, finishedChan, toHashChan, nil, nil)
		return finishedChan
	}

	// Defaults to every 2 seconds.
	if w.ProgressTickIntervalS == 0 {
		w.ProgressTickIntervalS = 2
	}

	// We need to emit progress events, hence we create a routine which buffers
	// the list of files to be hashed, counts the total number of
	// bytes to hash, and once no more files need to be hashed (chan gets closed),
	// start a routine which periodically emits FolderScanProgress events,
	// until a stop signal is sent by the parallel hasher.
	// Parallel hasher is stopped by this routine when we close the channel over
	// which it receives the files we ask it to hash.
	go func() {
		var filesToHash []protocol.FileInfo
		var total int64 = 1

		for file := range toHashChan {
			filesToHash = append(filesToHash, file)
			total += file.Size
		}

		if len(filesToHash) == 0 {
			close(finishedChan)
			return
		}

		realToHashChan := make(chan protocol.FileInfo)
		done := make(chan struct{})
		progress := newByteCounter()

		newParallelHasher(ctx, w.Folder, w.Filesystem, w.Hashers, finishedChan, realToHashChan, progress, done)

		// A routine which actually emits the FolderScanProgress events
		// every w.ProgressTicker ticks, until the hasher routines terminate.
		go func() {
			defer progress.Close()

			emitProgressEvent := func() {
				current := progress.Total()
				rate := progress.Rate()
				l.Debugf("%v: Walk %s %s current progress %d/%d at %.01f MiB/s (%d%%)", w, w.Folder, w.Subs, current, total, rate/1024/1024, current*100/total)
				w.EventLogger.Log(events.FolderScanProgress, map[string]interface{}{
					"folder":  w.Folder,
					"current": current,
					"total":   total,
					"rate":    rate, // bytes per second
				})
			}

			ticker := time.NewTicker(time.Duration(w.ProgressTickIntervalS) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					emitProgressEvent()
					l.Debugln(w, "Walk progress done", w.Folder, w.Subs, w.Matcher)
					return
				case <-ticker.C:
					emitProgressEvent()
				case <-ctx.Done():
					return
				}
			}
		}()

	loop:
		for _, file := range filesToHash {
			l.Debugln(w, "real to hash:", file.Name)
			select {
			case realToHashChan <- file:
			case <-ctx.Done():
				break loop
			}
		}
		close(realToHashChan)
	}()

	return finishedChan
}

func (w *walker) walkWithoutHashing(ctx context.Context) chan ScanResult {
	l.Debugln(w, "Walk without hashing", w.Subs, w.Matcher)

	toHashChan := make(chan protocol.FileInfo)
	finishedChan := make(chan ScanResult)

	// A routine which walks the filesystem tree, and sends files which have
	// been modified to the counter routine.
	go w.scan(ctx, toHashChan, finishedChan)

	go func() {
		for file := range toHashChan {
			finishedChan <- ScanResult{File: file}
		}
		close(finishedChan)
	}()

	return finishedChan
}

const walkFailureEventDesc = "Unexpected error while walking the filesystem during scan"
const defaultWalkWorkers = 4

func (w *walker) scan(ctx context.Context, toHashChan chan<- protocol.FileInfo, finishedChan chan<- ScanResult) {
	hashFiles := w.walkAndHashFiles(ctx, toHashChan, finishedChan)
	defer close(toHashChan)

	var starts []string
	if len(w.Subs) == 0 {
		starts = []string{"."}
	} else {
		for _, sub := range w.Subs {
			if err := osutil.TraversesSymlink(w.Filesystem, filepath.Dir(sub)); err != nil {
				l.Debugf("%v: Skip walking %v as it is below a symlink", w, sub)
				continue
			}
			starts = append(starts, sub)
		}
	}

	if err := w.walkWithScheduler(ctx, starts, hashFiles); isWarnableError(err) {
		w.EventLogger.Log(events.Failure, walkFailureEventDesc)
		slog.ErrorContext(ctx, "Aborted scan due to an unexpected error", slogutil.Error(err))
	}
}

func (w *walker) walkWithScheduler(ctx context.Context, starts []string, hashFiles fs.WalkFunc) error {
	if len(starts) == 0 {
		return nil
	}

	workers := w.Walkers
	if workers <= 0 {
		workers = defaultWalkWorkers
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type walkJob struct {
		path         string
		info         fs.FileInfo
		callbackDone bool
	}

	workBuf := workers * 2
	if workBuf < 4096 {
		workBuf = 4096
	}
	workCh := make(chan walkJob, workBuf)
	var pending sync.WaitGroup
	var run sync.WaitGroup
	var firstErr error
	var firstErrMut sync.Mutex

	setFirstErr := func(err error) {
		if err == nil {
			return
		}
		firstErrMut.Lock()
		defer firstErrMut.Unlock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
	}

	enqueue := func(job walkJob) bool {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		pending.Add(1)
		select {
		case workCh <- job:
			return true
		case <-ctx.Done():
			pending.Done()
			return false
		}
	}

	process := func(job walkJob) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		path := job.path
		info := job.info
		if !job.callbackDone {
			var err error
			info, err = w.Filesystem.Lstat(path)
			if err != nil {
				return hashFiles(path, nil, err)
			}

			if err := hashFiles(path, info, nil); err != nil {
				if errors.Is(err, fs.SkipDir) {
					return nil
				}
				return err
			}
		}
		if !info.IsDir() {
			return nil
		}

		names, err := w.Filesystem.DirNames(path)
		if err != nil {
			if err := hashFiles(path, info, err); errors.Is(err, fs.SkipDir) {
				return nil
			} else {
				return err
			}
		}
		slices.Sort(names)

		for _, name := range names {
			child := filepath.Join(path, name)
			childInfo, err := w.Filesystem.Lstat(child)
			walkErr := hashFiles(child, childInfo, err)
			switch {
			case errors.Is(walkErr, fs.SkipDir):
				continue
			case walkErr != nil:
				return walkErr
			case err == nil && childInfo.IsDir():
				if !enqueue(walkJob{path: child, info: childInfo, callbackDone: true}) {
					return ctx.Err()
				}
			}
		}
		return nil
	}

	run.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer run.Done()
			for job := range workCh {
				if err := process(job); err != nil {
					setFirstErr(err)
				}
				pending.Done()
			}
		}()
	}

	for _, start := range starts {
		if !enqueue(walkJob{path: start}) {
			break
		}
	}

	go func() {
		pending.Wait()
		close(workCh)
	}()

	run.Wait()
	return firstErr
}

// isWarnableError returns true if err is a kind of error we should warn
// about receiving from the folder walk.
func isWarnableError(err error) bool {
	return err != nil &&
		!errors.Is(err, fs.SkipDir) && // intentional skip
		!errors.Is(err, context.Canceled) // folder restarting
}

func (w *walker) walkAndHashFiles(ctx context.Context, toHashChan chan<- protocol.FileInfo, finishedChan chan<- ScanResult) fs.WalkFunc {
	now := time.Now()
	var ignoredDirsMut sync.Mutex
	handledIgnoredDirs := make(map[string]struct{})

	emitIgnoredAncestors := func(path string) error {
		var ignoredAncestors []string
		for parent := filepath.Dir(path); parent != "." && parent != ""; parent = filepath.Dir(parent) {
			if w.Matcher.Match(parent).IsIgnored() {
				ignoredAncestors = append(ignoredAncestors, parent)
			}
		}
		for i := len(ignoredAncestors) - 1; i >= 0; i-- {
			ignoredPath := ignoredAncestors[i]
			ignoredDirsMut.Lock()
			_, done := handledIgnoredDirs[ignoredPath]
			if !done {
				handledIgnoredDirs[ignoredPath] = struct{}{}
			}
			ignoredDirsMut.Unlock()
			if done {
				continue
			}

			info, err := w.Filesystem.Lstat(ignoredPath)
			if err != nil {
				return err
			}
			if err = w.handleItem(ctx, ignoredPath, info, toHashChan, finishedChan); err != nil {
				return err
			}
		}
		return nil
	}

	return func(path string, info fs.FileInfo, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		metricScannedItems.WithLabelValues(w.Folder).Inc()

		// Return value used when we are returning early and don't want to
		// process the item. For directories, this means do-not-descend.
		var skip error // nil
		// info nil when error is not nil
		if info != nil && info.IsDir() {
			skip = fs.SkipDir
		}

		if !utf8.ValidString(path) {
			handleError(ctx, "scan", path, errUTF8Invalid, finishedChan)
			return skip
		}

		if fs.IsTemporary(path) {
			l.Debugln(w, "temporary:", path, "err:", err)
			if err == nil && info.IsRegular() && info.ModTime().Add(w.TempLifetime).Before(now) {
				w.Filesystem.Remove(path)
				l.Debugln(w, "removing temporary:", path, info.ModTime())
			}
			return nil
		}

		if fs.IsInternal(path) {
			l.Debugln(w, "ignored (internal):", path)
			return skip
		}

		// Just in case the filesystem doesn't produce the normalization the OS
		// uses, and we use internally.
		nonNormPath := path
		path = normalizePath(path)

		if m := w.Matcher.Match(path); m.IsIgnored() {
			l.Debugln(w, "ignored (patterns):", path)
			// Only descend if matcher says so and the current file is not a symlink.
			if err != nil || m.CanSkipDir() || info.IsSymlink() {
				return skip
			}
			return nil
		}

		if err != nil {
			// No need reporting errors for files that don't exist (e.g. scan
			// due to filesystem watcher)
			if !fs.IsNotExist(err) {
				handleError(ctx, "scan", path, err, finishedChan)
			}
			return skip
		}

		if path == "." {
			return nil
		}

		if path != nonNormPath {
			if !w.AutoNormalize {
				// We're not authorized to do anything about it, so complain and skip.
				handleError(ctx, "normalizing path", nonNormPath, errUTF8Normalization, finishedChan)
				return skip
			}

			path, err = w.applyNormalization(nonNormPath, path, info)
			if err != nil {
				handleError(ctx, "normalizing path", nonNormPath, err, finishedChan)
				return skip
			}
		}

		if err := emitIgnoredAncestors(path); err != nil {
			handleError(ctx, "scan", path, err, finishedChan)
			return skip
		}

		if err := w.handleItem(ctx, path, info, toHashChan, finishedChan); err != nil {
			handleError(ctx, "scan", path, err, finishedChan)
			return skip
		}

		return nil
	}
}

// Returning an error does not indicate that the walk should be aborted - it
// will simply report the error for that path to the user (same for walk...
// functions called from here).
func (w *walker) handleItem(ctx context.Context, path string, info fs.FileInfo, toHashChan chan<- protocol.FileInfo, finishedChan chan<- ScanResult) error {
	switch {
	case info.IsSymlink():
		if err := w.walkSymlink(ctx, path, info, finishedChan); err != nil {
			return err
		}
		if info.IsDir() {
			// under no circumstances shall we descend into a symlink
			return fs.SkipDir
		}
		return nil

	case info.IsDir():
		return w.walkDir(ctx, path, info, finishedChan)

	case info.IsRegular():
		return w.walkRegular(ctx, path, info, toHashChan)

	default:
		// A special file, socket, fifo, etc. -- do nothing, just skip and continue scanning.
		l.Debugf("Skipping non-regular file %s (%s)", path, info.Mode())
		return nil
	}
}

func (w *walker) walkRegular(ctx context.Context, relPath string, info fs.FileInfo, toHashChan chan<- protocol.FileInfo) error {
	curFile, hasCurFile := w.CurrentFiler.CurrentFile(relPath)

	blockSize := protocol.BlockSize(info.Size())

	if hasCurFile {
		// Check if we should retain current block size.
		curBlockSize := curFile.BlockSize()
		if blockSize > curBlockSize && blockSize/curBlockSize <= 2 {
			// New block size is larger, but not more than twice larger.
			// Retain.
			blockSize = curBlockSize
		} else if curBlockSize > blockSize && curBlockSize/blockSize <= 2 {
			// Old block size is larger, but not more than twice larger.
			// Retain.
			blockSize = curBlockSize
		}
	}

	f, err := CreateFileInfo(info, relPath, w.Filesystem, w.ScanOwnership, w.ScanXattrs, w.XattrFilter)
	if err != nil {
		return err
	}
	f = w.updateFileInfo(f, curFile)
	f.NoPermissions = w.IgnorePerms
	f.RawBlockSize = int32(blockSize)
	l.Debugln(w, "checking:", f)

	if hasCurFile {
		if curFile.IsEquivalentOptional(f, protocol.FileInfoComparison{
			ModTimeWindow:   w.ModTimeWindow,
			IgnorePerms:     w.IgnorePerms,
			IgnoreBlocks:    true,
			IgnoreFlags:     w.LocalFlags,
			IgnoreOwnership: !w.ScanOwnership,
			IgnoreXattrs:    !w.ScanXattrs,
		}) {
			l.Debugln(w, "unchanged:", curFile)
			return nil
		}
		if curFile.ShouldConflict() && !f.ShouldConflict() {
			// The old file was invalid for whatever reason and probably not
			// up to date with what was out there in the cluster. Drop all
			// others from the version vector to indicate that we haven't
			// taken their version into account, and possibly cause a
			// conflict. However, only do this if the new file is not also
			// invalid. This would indicate that the new file is not part
			// of the cluster, but e.g. a local change.
			f.Version = f.Version.DropOthers(w.ShortID)
		}
		l.Debugln(w, "rescan:", curFile)
	}

	l.Debugln(w, "to hash:", relPath, f)

	select {
	case toHashChan <- f:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (w *walker) walkDir(ctx context.Context, relPath string, info fs.FileInfo, finishedChan chan<- ScanResult) error {
	curFile, hasCurFile := w.CurrentFiler.CurrentFile(relPath)

	f, err := CreateFileInfo(info, relPath, w.Filesystem, w.ScanOwnership, w.ScanXattrs, w.XattrFilter)
	if err != nil {
		return err
	}
	f = w.updateFileInfo(f, curFile)
	f.NoPermissions = w.IgnorePerms
	l.Debugln(w, "checking:", f)

	if hasCurFile {
		if curFile.IsEquivalentOptional(f, protocol.FileInfoComparison{
			ModTimeWindow:   w.ModTimeWindow,
			IgnorePerms:     w.IgnorePerms,
			IgnoreBlocks:    true,
			IgnoreFlags:     w.LocalFlags,
			IgnoreOwnership: !w.ScanOwnership,
			IgnoreXattrs:    !w.ScanXattrs,
		}) {
			l.Debugln(w, "unchanged:", curFile)
			return nil
		}
		if curFile.ShouldConflict() && !f.ShouldConflict() {
			// The old file was invalid for whatever reason and probably not
			// up to date with what was out there in the cluster. Drop all
			// others from the version vector to indicate that we haven't
			// taken their version into account, and possibly cause a
			// conflict. However, only do this if the new file is not also
			// invalid. This would indicate that the new file is not part
			// of the cluster, but e.g. a local change.
			f.Version = f.Version.DropOthers(w.ShortID)
		}
		l.Debugln(w, "rescan:", curFile)
	}

	l.Debugln(w, "dir:", relPath, f)

	select {
	case finishedChan <- ScanResult{File: f}:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (w *walker) walkSymlink(ctx context.Context, relPath string, info fs.FileInfo, finishedChan chan<- ScanResult) error {
	// Symlinks are not supported on Windows. We ignore instead of returning
	// an error.
	if build.IsWindows {
		return nil
	}

	f, err := CreateFileInfo(info, relPath, w.Filesystem, w.ScanOwnership, w.ScanXattrs, w.XattrFilter)
	if err != nil {
		return err
	}

	curFile, hasCurFile := w.CurrentFiler.CurrentFile(relPath)
	f = w.updateFileInfo(f, curFile)
	l.Debugln(w, "checking:", f)

	if hasCurFile {
		if curFile.IsEquivalentOptional(f, protocol.FileInfoComparison{
			ModTimeWindow:   w.ModTimeWindow,
			IgnorePerms:     w.IgnorePerms,
			IgnoreBlocks:    true,
			IgnoreFlags:     w.LocalFlags,
			IgnoreOwnership: !w.ScanOwnership,
			IgnoreXattrs:    !w.ScanXattrs,
		}) {
			l.Debugln(w, "unchanged:", curFile, info.ModTime().Unix(), info.Mode()&fs.ModePerm)
			return nil
		}
		if curFile.ShouldConflict() && !f.ShouldConflict() {
			// The old file was invalid for whatever reason and probably not
			// up to date with what was out there in the cluster. Drop all
			// others from the version vector to indicate that we haven't
			// taken their version into account, and possibly cause a
			// conflict. However, only do this if the new file is not also
			// invalid. This would indicate that the new file is not part
			// of the cluster, but e.g. a local change.
			f.Version = f.Version.DropOthers(w.ShortID)
		}
		l.Debugln(w, "rescan:", curFile)
	}

	l.Debugln(w, "symlink:", relPath, f)

	select {
	case finishedChan <- ScanResult{File: f}:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func normalizePath(path string) string {
	if build.IsDarwin || build.IsIOS {
		// Mac OS X file names should always be NFD normalized.
		return norm.NFD.String(path)
	}
	// Every other OS in the known universe uses NFC or just plain
	// doesn't bother to define an encoding. In our case *we* do care,
	// so we enforce NFC regardless.
	return norm.NFC.String(path)
}

// applyNormalization fixes the normalization of the file on disk, i.e. ensures
// the file at path ends up named normPath. It shouldn't but may happen that the
// file ends up with a different name, in which case that one should be scanned.
func (w *walker) applyNormalization(path, normPath string, info fs.FileInfo) (string, error) {
	// We will attempt to normalize it.
	normInfo, err := w.Filesystem.Lstat(normPath)
	if fs.IsNotExist(err) {
		// Nothing exists with the normalized filename. Good.
		if err = w.Filesystem.Rename(path, normPath); err != nil {
			return "", err
		}
		slog.Info("Normalized UTF8 encoding of file name", slogutil.FilePath(path))
		return normPath, nil
	}
	if w.Filesystem.SameFile(info, normInfo) {
		// With some filesystems (ZFS), if there is an un-normalized path and you ask whether the normalized
		// version exists, it responds with true. Therefore we need to check fs.SameFile as well.
		// In this case, a call to Rename won't do anything, so we have to rename via a temp file.

		// We don't want to use the standard syncthing prefix here, as that will result in the file being ignored
		// and eventually deleted by Syncthing if the rename back fails.

		tempPath := fs.TempNameWithPrefix(normPath, "")
		if err = w.Filesystem.Rename(path, tempPath); err != nil {
			return "", err
		}
		if err = w.Filesystem.Rename(tempPath, normPath); err != nil {
			// I don't ever expect this to happen, but if it does, we should probably tell our caller that the normalized
			// path is the temp path: that way at least the user's data still gets synced.
			slog.Error("Failed to rename while normalizating UTF8 encoding; please rename temp file manually", slog.String("from", tempPath), slog.String("to", normPath), slogutil.Error(err))
			return tempPath, nil
		}
		return normPath, nil
	}
	// There is something already in the way at the normalized
	// file name.
	return "", errUTF8Conflict
}

// updateFileInfo updates walker specific members of protocol.FileInfo that
// do not depend on type, and things that should be preserved from the
// previous version of the FileInfo.
func (w *walker) updateFileInfo(dst, src protocol.FileInfo) protocol.FileInfo {
	if dst.Type == protocol.FileInfoTypeFile && build.IsWindows {
		// If we have an existing index entry, copy the executable bits
		// from there.
		dst.Permissions |= (src.Permissions & 0o111)
	}
	dst.Version = src.Version.Update(w.ShortID)
	dst.ModifiedBy = w.ShortID
	dst.LocalFlags = w.LocalFlags
	dst.PreviousBlocksHash = src.BlocksHash

	// Copy OS data from src to dst, unless it was already set on dst.
	dst.Platform.MergeWith(&src.Platform)

	return dst
}

func handleError(ctx context.Context, context, path string, err error, finishedChan chan<- ScanResult) {
	l.Debugf("handle error on '%v': %v: %v", path, context, err)
	select {
	case finishedChan <- ScanResult{
		Err:  fmt.Errorf("%s: %w", context, err),
		Path: path,
	}:
	case <-ctx.Done():
	}
}

func (w *walker) String() string {
	return fmt.Sprintf("walker/%s@%p", w.Folder, w)
}

// A byteCounter gets bytes added to it via Update() and then provides the
// Total() and one minute moving average Rate() in bytes per second.
type byteCounter struct {
	metrics.EWMA

	total atomic.Int64
	stop  chan struct{}
}

func newByteCounter() *byteCounter {
	c := &byteCounter{
		EWMA: metrics.NewEWMA1(), // a one minute exponentially weighted moving average
		stop: make(chan struct{}),
	}
	go c.ticker()
	return c
}

func (c *byteCounter) ticker() {
	// The metrics.EWMA expects clock ticks every five seconds in order to
	// decay the average properly.
	t := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-t.C:
			c.Tick()
		case <-c.stop:
			t.Stop()
			return
		}
	}
}

func (c *byteCounter) Update(bytes int64) {
	c.total.Add(bytes)
	c.EWMA.Update(bytes)
}

func (c *byteCounter) Total() int64 { return c.total.Load() }

func (c *byteCounter) Close() {
	close(c.stop)
}

// A no-op CurrentFiler

type noCurrentFiler struct{}

func (noCurrentFiler) CurrentFile(_ string) (protocol.FileInfo, bool) {
	return protocol.FileInfo{}, false
}

func CreateFileInfo(fi fs.FileInfo, name string, filesystem fs.Filesystem, scanOwnership bool, scanXattrs bool, xattrFilter XattrFilter) (protocol.FileInfo, error) {
	f := protocol.FileInfo{Name: name}
	if scanOwnership || scanXattrs {
		if plat, err := filesystem.PlatformData(name, scanOwnership, scanXattrs, xattrFilter); err == nil {
			f.Platform = plat
		} else {
			return protocol.FileInfo{}, fmt.Errorf("reading platform data: %w", err)
		}
	}

	if fi.IsSymlink() {
		f.Type = protocol.FileInfoTypeSymlink
		target, err := filesystem.ReadSymlink(name)
		if err != nil {
			return protocol.FileInfo{}, err
		}
		f.SymlinkTarget = []byte(target)
		f.NoPermissions = true // Symlinks don't have permissions of their own
		return f, nil
	}

	f.Permissions = uint32(fi.Mode() & fs.ModePerm)
	f.ModifiedS = fi.ModTime().Unix()
	f.ModifiedNs = int32(fi.ModTime().Nanosecond())

	if fi.IsDir() {
		f.Type = protocol.FileInfoTypeDirectory
		return f, nil
	}

	f.Size = fi.Size()
	f.Type = protocol.FileInfoTypeFile

	return f, nil
}
