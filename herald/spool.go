package herald

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// spool keeps undelivered events as one file each in a directory of its own. File names start
// with the time of the first attempt, so a sorted listing is the order to replay in. The
// directory is opened as a root: no file name can lead outside it.
type spool struct {
	root *os.Root
}

const (
	spoolSuffix = ".json"
	// spoolFileMode: an event may carry private text, so only the owner reads it.
	spoolFileMode = 0o600
	spoolDirMode  = 0o700
)

func openSpool(dir string) (*spool, error) {
	if err := os.MkdirAll(dir, spoolDirMode); err != nil {
		return nil, fmt.Errorf("herald: create spool directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("herald: open spool directory: %w", err)
	}
	return &spool{root: root}, nil
}

// put writes one event so that a crash leaves either the whole file or none: a temporary name
// first, then a rename.
func (s *spool) put(firstAttempt time.Time, eventID string, body []byte) error {
	name := fmt.Sprintf("%020d-%s%s", firstAttempt.UnixNano(), eventID, spoolSuffix)
	temporary := name + ".tmp"
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, spoolFileMode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close() // the write error is the one worth reporting
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close() // as above
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return s.root.Rename(temporary, name)
}

// list returns the spooled files, oldest first. Half-written temporary files are not events.
func (s *spool) list() ([]string, error) {
	dir, err := s.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("herald: read spool: %w", err)
	}
	defer func() { _ = dir.Close() }() // read-only: a close error loses nothing
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("herald: read spool: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), spoolSuffix) {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

func (s *spool) read(name string) ([]byte, error) {
	return s.root.ReadFile(name)
}

func (s *spool) remove(name string) error {
	if err := s.root.Remove(name); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("herald: remove spooled event: %w", err)
	}
	return nil
}

// eventIDOf returns the event ID inside a spool file name.
func eventIDOf(name string) string {
	_, id, _ := strings.Cut(strings.TrimSuffix(name, spoolSuffix), "-")
	return id
}
