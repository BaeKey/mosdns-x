package data_provider

import "testing"

func TestDataProvider_dataHashChanged(t *testing.T) {
	dp := new(DataProvider)

	if !dp.dataHashChanged([]byte("a")) {
		t.Fatal("first data should be treated as changed")
	}
	if dp.dataHashChanged([]byte("a")) {
		t.Fatal("same data should not be treated as changed")
	}
	if !dp.dataHashChanged([]byte("b")) {
		t.Fatal("different data should be treated as changed")
	}
}
