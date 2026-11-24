package secret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return path
}

func input(value, path string) Input {
	return Input{Name: "APP_TOKEN", FileName: "APP_TOKEN_FILE", Value: value, Path: path}
}

func TestStrictResolve(t *testing.T) {
	tests := []struct {
		name    string
		in      func(t *testing.T) Input
		want    string
		wantErr error
	}{
		{"nothing configured", func(*testing.T) Input { return input("", "") }, "", nil},
		{"value is returned unchanged", func(*testing.T) Input { return input(" pass word ", "") }, " pass word ", nil},
		{"blank value", func(*testing.T) Input { return input("  ", "") }, "", ErrEmpty},
		{"file loses only its line break", func(t *testing.T) Input { return input("", writeFile(t, " s3cret \r\n")) }, " s3cret ", nil},
		{"path is trimmed", func(t *testing.T) Input { return input("", "  "+writeFile(t, "abc\n")+" ") }, "abc", nil},
		{"value and file", func(t *testing.T) Input { return input("abc", writeFile(t, "abc")) }, "", ErrBothSet},
		{"empty file", func(t *testing.T) Input { return input("", writeFile(t, "")) }, "", ErrEmpty},
		{"file with white space only", func(t *testing.T) Input { return input("", writeFile(t, " \n\n")) }, "", ErrEmpty},
		{"missing file", func(t *testing.T) Input { return input("", filepath.Join(t.TempDir(), "absent")) }, "", os.ErrNotExist},
		{"directory", func(t *testing.T) Input { return input("", t.TempDir()) }, "", ErrNotRegularFile},
		{"file above the limit", func(t *testing.T) Input {
			in := input("", writeFile(t, "123456789"))
			in.MaxBytes = 8
			return in
		}, "", ErrTooLarge},
		{"file exactly at the limit", func(t *testing.T) Input {
			in := input("", writeFile(t, "12345678"))
			in.MaxBytes = 8
			return in
		}, "12345678", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.in(t), Strict)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("Resolve = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStrictRefusesSymlink(t *testing.T) {
	target := writeFile(t, "s3cret")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this system cannot create a symlink: %v", err)
	}
	if _, err := Resolve(input("", link), Strict); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("Resolve through a symlink: error = %v, want ErrNotRegularFile", err)
	}
}

func TestErrorsNameTheSettingAndNeverTheSecret(t *testing.T) {
	const value = "do-not-print-me"
	_, err := Resolve(input(value, writeFile(t, value)), Strict)
	if err == nil || !strings.Contains(err.Error(), "APP_TOKEN and APP_TOKEN_FILE") {
		t.Fatalf("error %v does not name both settings", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error %q contains the secret", err)
	}

	in := input("", writeFile(t, value+value))
	in.MaxBytes = 4
	_, err = Resolve(in, Strict)
	if err == nil || !strings.Contains(err.Error(), "APP_TOKEN_FILE") || strings.Contains(err.Error(), value) {
		t.Fatalf("size error %v must name the file setting and not the content", err)
	}
}

func TestLegacyResolve(t *testing.T) {
	tests := []struct {
		name string
		in   func(t *testing.T) Input
		want string
	}{
		{"nothing configured", func(*testing.T) Input { return input("", "") }, ""},
		{"value wins over the file", func(t *testing.T) Input { return input("direct", writeFile(t, "from-file")) }, "direct"},
		{"blank value falls back to the file", func(t *testing.T) Input { return input("  ", writeFile(t, "from-file\n")) }, "from-file"},
		{"empty file is an empty secret", func(t *testing.T) Input { return input("", writeFile(t, "\n")) }, ""},
		{"inner and leading spaces stay", func(t *testing.T) Input { return input("", writeFile(t, " a b \n")) }, " a b "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.in(t), Legacy)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Resolve = %q, want %q", got, tc.want)
			}
		})
	}

	if _, err := Resolve(input("", filepath.Join(t.TempDir(), "absent")), Legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: error = %v, want os.ErrNotExist", err)
	}
}

func TestLegacyFollowsSymlink(t *testing.T) {
	target := writeFile(t, "s3cret\n")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this system cannot create a symlink: %v", err)
	}
	got, err := Resolve(input("", link), Legacy)
	if err != nil || got != "s3cret" {
		t.Fatalf("Resolve through a symlink = %q, %v; legacy mode reads it", got, err)
	}
}
