package common

import (
	"io"
	"strings"
)

// Closable is the interface for objects that can release its resources.
type Closable interface {
	// Close release all resources used by this object, including goroutines.
	Close() error
}

// Interruptible is an interface for objects that can be stopped before its completion.
type Interruptible interface {
	Interrupt()
}

// Close closes the obj if it is a Closable.
func Close(obj any) error {
	if c, ok := obj.(Closable); ok {
		return c.Close()
	}
	return nil
}

// Interrupt calls Interrupt() if object implements Interruptible interface, or Close() if the object implements Closable interface.
func Interrupt(obj any) error {
	if c, ok := obj.(Interruptible); ok {
		c.Interrupt()
		return nil
	}
	return Close(obj)
}

// ChainedClosable is a Closable that consists of multiple Closable objects.
type ChainedClosable []Closable

// Close implements Closable.
func (cc ChainedClosable) Close() error {
	var errs []error
	for _, c := range cc {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return combine(errs...)
}

type multiError []error

func (e multiError) Error() string {
	var r strings.Builder
	r.WriteString("multierr: ")
	for _, err := range e {
		r.WriteString(err.Error())
		r.WriteString(" | ")
	}
	return r.String()
}

func combine(maybeError ...error) error {
	var errs multiError
	for _, err := range maybeError {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// Must panics if err is not nil.
func Must(err error) {
	if err != nil {
		panic(err)
	}
}
func contains(err error, msgList ...string) bool {
	for _, msg := range msgList {
		if strings.Contains(err.Error(), msg) {
			return true
		}
	}
	return false
}

func WrapH2(err error) error {
	if err == nil {
		return nil
	}
	err = unwrap(err)
	if err == io.ErrUnexpectedEOF {
		return io.EOF
	}
	if contains(err, "client disconnected", "body closed by handler", "response body closed", "; CANCEL") {
		//return net.ErrClosed
		return io.EOF
	}
	return err
}

type hasInnerError interface {
	unwrap() error
}

func unwrap(err error) error {
	for {
		inner, ok := err.(hasInnerError)
		if !ok {
			break
		}
		innerErr := inner.unwrap()
		if innerErr == nil {
			break
		}
		err = innerErr
	}
	return err
}
