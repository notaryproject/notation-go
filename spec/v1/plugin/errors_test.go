package plugin

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestRequestError_Error(t *testing.T) {
	err := RequestError{Code: ErrorCodeAccessDenied, Err: errors.New("an error")}
	want := string(ErrorCodeAccessDenied) + ": an error"
	if got := err.Error(); got != want {
		t.Errorf("RequestError.Error() = %v, want %v", got, want)
	}
}

func TestRequestError_Unwrap(t *testing.T) {
	want := errors.New("an error")
	got := RequestError{Code: ErrorCodeAccessDenied, Err: want}.Unwrap()
	if got != want {
		t.Errorf("RequestError.Unwrap() = %v, want %v", got, want)
	}
}

func TestRequestError_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		e    RequestError
		want []byte
	}{
		{"empty", RequestError{}, []byte("{\"errorCode\":\"\"}")},
		{"with code", RequestError{Code: ErrorCodeAccessDenied}, []byte("{\"errorCode\":\"ACCESS_DENIED\"}")},
		{"with message", RequestError{Code: ErrorCodeAccessDenied, Err: errors.New("failed")}, []byte("{\"errorCode\":\"ACCESS_DENIED\",\"errorMessage\":\"failed\"}")},
		{
			"with metadata",
			RequestError{Code: ErrorCodeAccessDenied, Err: errors.New("failed"), Metadata: map[string]string{"a": "b"}},
			[]byte("{\"errorCode\":\"ACCESS_DENIED\",\"errorMessage\":\"failed\",\"errorMetadata\":{\"a\":\"b\"}}"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.e.MarshalJSON()
			if err != nil {
				t.Fatalf("RequestError.MarshalJSON() error = %v, wantErr false", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("RequestError.MarshalJSON() = %s, want %s", got, tt.want)
			}
			if tt.e.Code == "" {
				return
			}
			var got1 RequestError
			err = json.Unmarshal(got, &got1)
			if err != nil {
				t.Fatalf("RequestError.UnmarshalJSON() error = %v, wantErr false", err)
			}
			if got1.Code != tt.e.Code || !reflect.DeepEqual(got1.Metadata, tt.e.Metadata) {
				t.Fatalf("RequestError.UnmarshalJSON() = %s, want %s", got1, tt.e)
			}
		})
	}
}

func TestRequestError_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    RequestError
		wantErr bool
	}{
		{"invalid", args{[]byte("")}, RequestError{}, true},
		{"empty", args{[]byte("{}")}, RequestError{}, true},
		{"with code", args{[]byte("{\"errorCode\":\"ACCESS_DENIED\"}")}, RequestError{Code: ErrorCodeAccessDenied}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e RequestError
			if err := e.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("RequestError.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && (e.Code != tt.want.Code || !reflect.DeepEqual(e.Metadata, tt.want.Metadata)) {
				t.Fatalf("RequestError.UnmarshalJSON() = %s, want %s", e, tt.want)
			}
		})
	}
}

func TestRequestError_Is(t *testing.T) {
	type args struct {
		target error
	}
	tests := []struct {
		name string
		e    RequestError
		args args
		want bool
	}{
		{"nil", RequestError{}, args{nil}, false},
		{"not same type", RequestError{Err: errors.New("foo")}, args{errors.New("foo")}, false},
		{"only same code", RequestError{Code: ErrorCodeGeneric, Err: errors.New("foo")}, args{RequestError{Code: ErrorCodeGeneric, Err: errors.New("bar")}}, false},
		{"only same message", RequestError{Code: ErrorCodeTimeout, Err: errors.New("foo")}, args{RequestError{Code: ErrorCodeGeneric, Err: errors.New("foo")}}, false},
		{"same with nil message", RequestError{Code: ErrorCodeGeneric}, args{RequestError{Code: ErrorCodeGeneric}}, true},
		{"same", RequestError{Code: ErrorCodeGeneric, Err: errors.New("foo")}, args{RequestError{Code: ErrorCodeGeneric, Err: errors.New("foo")}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Is(tt.args.target); got != tt.want {
				t.Errorf("RequestError.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
