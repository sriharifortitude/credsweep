package gitdiff

import (
	"reflect"
	"testing"
)

func TestParseExtractsAddedLinesWithTheirNewFileLineNumber(t *testing.T) {
	patch := `diff --git a/config.env b/config.env
index e69de29..3b18e51 100644
--- a/config.env
+++ b/config.env
@@ -0,0 +1,2 @@
+FIRST=one
+SECOND=two
`
	got := Parse(patch)
	want := []FileDiff{{
		Path: "config.env",
		Added: []AddedLine{
			{Line: 1, Text: "FIRST=one"},
			{Line: 2, Text: "SECOND=two"},
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseTracksLineNumberAcrossAMixOfContextAndAddedLines(t *testing.T) {
	// --unified=0 normally omits context, but a hunk can still carry it
	// (e.g. a manually constructed patch, or a future git default change),
	// so context lines must still advance the new-file line counter.
	patch := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import os
+API_KEY = "x"
 print(os.getenv("X"))
`
	got := Parse(patch)
	want := []FileDiff{{
		Path:  "app.py",
		Added: []AddedLine{{Line: 2, Text: `API_KEY = "x"`}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseHandlesMultipleHunksInOneFile(t *testing.T) {
	patch := `diff --git a/two.txt b/two.txt
--- a/two.txt
+++ b/two.txt
@@ -1,0 +2 @@
+top secret
@@ -10,0 +12 @@
+also secret
`
	got := Parse(patch)
	want := []FileDiff{{
		Path: "two.txt",
		Added: []AddedLine{
			{Line: 2, Text: "top secret"},
			{Line: 12, Text: "also secret"},
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseSkipsFilesThatWereOnlyDeleted(t *testing.T) {
	patch := `diff --git a/gone.txt b/gone.txt
deleted file mode 100644
index 3b18e51..0000000
--- a/gone.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-FIRST=one
-SECOND=two
`
	got := Parse(patch)
	if len(got) != 0 {
		t.Fatalf("expected no FileDiff for a pure deletion, got %+v", got)
	}
}

func TestParseSkipsBinaryFiles(t *testing.T) {
	patch := `diff --git a/image.png b/image.png
index e69de29..3b18e51 100644
Binary files a/image.png and b/image.png differ
`
	got := Parse(patch)
	if len(got) != 0 {
		t.Fatalf("expected no FileDiff for a binary file, got %+v", got)
	}
}

func TestParseHandlesMultipleFilesInOnePatch(t *testing.T) {
	patch := `diff --git a/one.txt b/one.txt
--- a/one.txt
+++ b/one.txt
@@ -0,0 +1 @@
+alpha
diff --git a/two.txt b/two.txt
--- a/two.txt
+++ b/two.txt
@@ -0,0 +1 @@
+beta
`
	got := Parse(patch)
	want := []FileDiff{
		{Path: "one.txt", Added: []AddedLine{{Line: 1, Text: "alpha"}}},
		{Path: "two.txt", Added: []AddedLine{{Line: 1, Text: "beta"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseIgnoresRemovedLinesEntirely(t *testing.T) {
	patch := `diff --git a/one.txt b/one.txt
--- a/one.txt
+++ b/one.txt
@@ -1,2 +1 @@
-removed line
 kept line
`
	got := Parse(patch)
	if len(got) != 0 {
		t.Fatalf("a hunk with no added lines should yield no FileDiff, got %+v", got)
	}
}

func TestParseOfEmptyPatchIsEmpty(t *testing.T) {
	if got := Parse(""); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}
