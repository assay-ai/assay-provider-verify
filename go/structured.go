package assayverify

import (
	"errors"
	"strconv"
	"strings"
)

// Minimal RFC 8941 parser: dictionaries whose members are inner lists of
// strings or single items (integer, string, token, byte sequence), with
// parameters. Only what the Assay signature headers need.

type bareKind int

const (
	kindString bareKind = iota // quoted string or token
	kindInt
	kindBytes // s holds the base64 text
	kindBool
)

type bare struct {
	kind bareKind
	s    string
	n    int64
}

type member struct {
	list   []string // string items of an inner list
	isList bool
	item   *bare // single item, when not an inner list
	params map[string]bare
	raw    string // text after "name=": inner list or item, plus params
}

var errParse = errors.New("structured field parse error")

type cursor struct {
	s string
	i int
}

func (c *cursor) eof() bool { return c.i >= len(c.s) }
func (c *cursor) peek() byte {
	if c.eof() {
		return 0
	}
	return c.s[c.i]
}
func (c *cursor) skip(set string) {
	for !c.eof() && strings.IndexByte(set, c.s[c.i]) >= 0 {
		c.i++
	}
}

func isLower(b byte) bool { return b >= 'a' && b <= 'z' }
func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool { return isLower(b) || (b >= 'A' && b <= 'Z') }

func parseKey(c *cursor) (string, error) {
	start := c.i
	if c.eof() || !(isLower(c.peek()) || c.peek() == '*') {
		return "", errParse
	}
	for !c.eof() {
		b := c.peek()
		if !(isLower(b) || isDigit(b) || b == '_' || b == '-' || b == '.' || b == '*') {
			break
		}
		c.i++
	}
	return c.s[start:c.i], nil
}

func isB64(s string) bool {
	body := strings.TrimRight(s, "=")
	if len(s)-len(body) > 2 {
		return false
	}
	for i := 0; i < len(body); i++ {
		b := body[i]
		if !(isAlpha(b) || isDigit(b) || b == '+' || b == '/') {
			return false
		}
	}
	return true
}

const tokenChars = "!#$%&'*+-.^_`|~:/"

func parseBare(c *cursor) (bare, error) {
	ch := c.peek()
	switch {
	case ch == '"':
		c.i++
		var sb strings.Builder
		for {
			if c.eof() {
				return bare{}, errParse
			}
			x := c.s[c.i]
			c.i++
			if x == '"' {
				return bare{kind: kindString, s: sb.String()}, nil
			}
			if x == '\\' {
				if c.eof() {
					return bare{}, errParse
				}
				n := c.s[c.i]
				c.i++
				if n != '"' && n != '\\' {
					return bare{}, errParse
				}
				sb.WriteByte(n)
				continue
			}
			if x < 0x20 || x > 0x7e {
				return bare{}, errParse
			}
			sb.WriteByte(x)
		}
	case ch == ':':
		c.i++
		end := strings.IndexByte(c.s[c.i:], ':')
		if end < 0 {
			return bare{}, errParse
		}
		b64 := c.s[c.i : c.i+end]
		if !isB64(b64) {
			return bare{}, errParse
		}
		c.i += end + 1
		return bare{kind: kindBytes, s: b64}, nil
	case ch == '-' || isDigit(ch):
		start := c.i
		if ch == '-' {
			c.i++
		}
		digits := c.i
		for !c.eof() && isDigit(c.peek()) && c.i-digits < 15 {
			c.i++
		}
		if c.i == digits || c.peek() == '.' {
			return bare{}, errParse
		}
		n, err := strconv.ParseInt(c.s[start:c.i], 10, 64)
		if err != nil {
			return bare{}, errParse
		}
		return bare{kind: kindInt, n: n}, nil
	case isAlpha(ch) || ch == '*':
		start := c.i
		for !c.eof() {
			b := c.peek()
			if !(isAlpha(b) || isDigit(b) || strings.IndexByte(tokenChars, b) >= 0) {
				break
			}
			c.i++
		}
		return bare{kind: kindString, s: c.s[start:c.i]}, nil
	}
	return bare{}, errParse
}

func parseParams(c *cursor) (map[string]bare, error) {
	params := map[string]bare{}
	for c.peek() == ';' {
		c.i++
		c.skip(" ")
		key, err := parseKey(c)
		if err != nil {
			return nil, err
		}
		value := bare{kind: kindBool}
		if c.peek() == '=' {
			c.i++
			if value, err = parseBare(c); err != nil {
				return nil, err
			}
		}
		params[key] = value
	}
	return params, nil
}

// parseDictionary parses a dictionary header value into its members. A repeated
// key keeps the last value.
func parseDictionary(input string) (map[string]member, error) {
	c := &cursor{s: input}
	out := map[string]member{}
	c.skip(" \t")
	for !c.eof() {
		key, err := parseKey(c)
		if err != nil {
			return nil, err
		}
		var m member
		if c.peek() == '=' {
			c.i++
			start := c.i
			if c.peek() == '(' {
				c.i++
				m.isList = true
				for {
					c.skip(" ")
					if c.peek() == ')' {
						c.i++
						break
					}
					v, err := parseBare(c)
					if err != nil || v.kind != kindString {
						return nil, errParse
					}
					m.list = append(m.list, v.s)
					if n := c.peek(); n != ' ' && n != ')' {
						return nil, errParse
					}
				}
			} else {
				v, err := parseBare(c)
				if err != nil {
					return nil, err
				}
				m.item = &v
			}
			if m.params, err = parseParams(c); err != nil {
				return nil, err
			}
			m.raw = c.s[start:c.i]
		} else {
			m.item = &bare{kind: kindString, s: "true"}
			if m.params, err = parseParams(c); err != nil {
				return nil, err
			}
		}
		out[key] = m
		c.skip(" \t")
		if c.eof() {
			break
		}
		if c.peek() != ',' {
			return nil, errParse
		}
		c.i++
		c.skip(" \t")
		if c.eof() {
			return nil, errParse
		}
	}
	return out, nil
}
