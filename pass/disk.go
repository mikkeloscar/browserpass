package pass

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mattn/go-zglob"
	"github.com/mattn/go-zglob/fastwalk"
)

type diskStore struct {
	path string
}

func NewDefaultStore() (Store, error) {
	path, err := defaultStorePath()
	if err != nil {
		return nil, err
	}

	return &diskStore{path}, nil
}

func defaultStorePath() (string, error) {
	path := os.Getenv("PASSWORD_STORE_DIR")
	if path == "" {
		path = filepath.Join(os.Getenv("HOME"), ".password-store")
	}

	// Follow symlinks
	return filepath.EvalSymlinks(path)
}

func lookup(domain string, sites []*site) []*site {
	results := make([]*site, 0)
	domainParts := reverse(strings.Split(domain, "."))
	for _, s := range sites {
		parts := reverse(strings.Split(s.domain, "."))
		if subMatch(domainParts, parts, 2) {
			results = append(results, s)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return len(results[i].domain) > len(results[j].domain)
	})

	return results
}

func reverse(strings []string) []string {
	for i, j := 0, len(strings)-1; i < j; i, j = i+1, j-1 {
		strings[i], strings[j] = strings[j], strings[i]
	}

	return strings
}

func subMatch(x, y []string, min int) bool {
	if len(y) < min {
		return false
	}

	if len(x) < len(y) {
		return false
	}

	matches := 0
	for i := len(y) - 1; i > -1; i-- {
		if y[i] == x[i] {
			matches++
		} else {
			return false
		}

		if matches >= min {
			return true
		}
	}

	return false
}

type site struct {
	domain string
	users  []string
}

func (s *diskStore) Lookup(query string) ([]string, error) {
	sites := make([]*site, 0)
	siteCh := make(chan *site)
	go func() {
		for site := range siteCh {
			sites = append(sites, site)
		}
	}()

	err := fastwalk.FastWalk(s.path, func(dir string, typ os.FileMode) error {
		if dir == s.path {
			return nil
		}
		if typ&os.ModeDir != 0 {
			files, err := ioutil.ReadDir(dir)
			if err != nil {
				return err
			}

			users := make([]string, 0, len(files))
			for _, file := range files {
				users = append(users, strings.TrimSuffix(file.Name(), ".gpg"))
			}
			siteCh <- &site{domain: path.Base(dir), users: users}
			return filepath.SkipDir
		}

		return nil
	})
	close(siteCh)
	if err != nil {
		return nil, err
	}

	sites = lookup(query, sites)

	results := make([]string, 0, len(sites))
	for _, site := range sites {
		for _, user := range site.users {
			results = append(results, site.domain+"/"+user)
		}
	}

	return results, nil
}

func (s *diskStore) Search(query string) ([]string, error) {
	// First, search for DOMAIN/USERNAME.gpg
	// Then, search for DOMAIN.gpg
	matches, err := zglob.Glob(s.path + "/**/" + query + "*/*.gpg")
	if err != nil {
		return nil, err
	}

	matches2, err := zglob.Glob(s.path + "/**/" + query + "*.gpg")
	if err != nil {
		return nil, err
	}

	items := append(matches, matches2...)
	for i, path := range items {
		item, err := filepath.Rel(s.path, path)
		if err != nil {
			return nil, err
		}
		items[i] = strings.TrimSuffix(item, ".gpg")
	}

	return items, nil
}

func (s *diskStore) Open(item string) (io.ReadCloser, error) {
	p := filepath.Join(s.path, item+".gpg")
	if !filepath.HasPrefix(p, s.path) {
		// Make sure the requested item is *in* the password store
		return nil, errors.New("invalid item path")
	}

	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return f, err
}
