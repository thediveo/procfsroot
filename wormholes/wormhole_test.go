// Copyright 2026 Harald Albrecht.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wormholes

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/thediveo/success"
)

func whfs() *FS {
	return New(os.Getpid())
}

func testdataPath(testpath string) string {
	GinkgoHelper()
	return Successful(filepath.Abs(filepath.Join("./_testdata", testpath)))[1:]
}

var _ = Describe("wormhole FS", func() {

	It("returns the PID", func() {
		Expect(New(1).PID()).To(Equal(1))
	})

	When("asking for a subtree FS", func() {

		It("rejects invalid dirs", func() {
			Expect(whfs().Sub("/subdir")).Error().To(HaveOccurred())
		})

		It("handles the same dir", func() {
			sub := Successful(whfs().Sub("."))
			Expect(fs.ReadFile(sub, testdataPath("canary.txt"))).Error().NotTo(HaveOccurred())
		})

		It("reads the link in the subdir", func() {
			sub := Successful(whfs().Sub(testdataPath("subdir")))
			Expect(fs.ReadLink(sub, "linky")).Error().NotTo(HaveOccurred())
		})

	})

	When("opening files", func() {

		It("fails if no access, surfacing the open error", func() {
			if os.Getuid() == 0 {
				Skip("don't be root")
			}
			wh := New(1)
			Expect(wh.Open("etc/hostname")).Error().To(MatchError(
				ContainSubstring(`/proc/1/root/etc: permission denied`)))
		})

		It("opens canary.txt", func() {
			f := Successful(whfs().Open(testdataPath("canary.txt")))
			Expect(Successful(io.ReadAll(f))).To(BeEquivalentTo("beep\n"))
		})

		It("opens symlink'd linky", func() {
			f := Successful(whfs().Open(testdataPath("subdir/linky")))
			Expect(Successful(io.ReadAll(f))).To(BeEquivalentTo("beep\n"))
		})

		It("reports non-existing file", func() {
			Expect(whfs().Open(testdataPath("does-not-exist.sanity"))).Error().To(
				MatchError(ContainSubstring("no such file or directory")))
		})

	})

	When("reading file contents", func() {

		It("rejects invalid names", func() {
			Expect(whfs().ReadFile("")).Error().To(HaveOccurred())
		})

		It("reads canary.txt", func() {
			Expect(whfs().ReadFile(testdataPath("canary.txt"))).To(BeEquivalentTo("beep\n"))
		})

	})

	When("stat'ing files", func() {

		It("rejects invalid names", func() {
			Expect(whfs().Stat("")).Error().To(HaveOccurred())
		})

		It("stat's the link's destination", func() {
			Expect(whfs().Stat(testdataPath("subdir/linky"))).To(
				HaveField("Name()", "canary.txt"))
		})

	})

	When("reading directories", func() {

		It("rejects invalid names", func() {
			Expect(whfs().ReadDir("")).Error().To(HaveOccurred())
		})

		It("reports an error when trying to read a file", func() {
			Expect(whfs().ReadDir(testdataPath("canary.txt"))).Error().To(HaveOccurred())
		})

		It("returns the expected entries", func() {
			entries := Successful(whfs().ReadDir(testdataPath(".")))
			Expect(entries).To(ConsistOf(
				And(HaveField("Name()", "canary.txt"),
					HaveField("IsDir()", false)),
				And(HaveField("Name()", "subdir"),
					HaveField("IsDir()", true)),
			))
		})

		It("reads the root '.'", func() {
			// This exercises also the evilSymlinks path for "." aka "/"
			Expect(Successful(whfs().ReadDir("."))).NotTo(BeEmpty())
		})

	})

	When("reading links", func() {

		It("rejects invalid names", func() {
			Expect(whfs().ReadLink("")).Error().To(HaveOccurred())
		})

		It("reports an error when trying to read a file as a link", func() {
			Expect(whfs().ReadLink(testdataPath("subdir"))).Error().To(HaveOccurred())
		})

		It("returns the expected destination", func() {
			Expect(Successful(whfs().ReadLink(testdataPath("subdir/linky")))).To(
				// looking at dirFS.ReadLink
				// (https://cs.opensource.google/go/go/+/refs/tags/go1.27.0:src/os/file.go;l=837)
				// the result of reading the link verbatim...
				Equal("../canary.txt"))
		})

	})

	When("stat'ing the link", func() {

		It("rejects invalid names", func() {
			Expect(whfs().Lstat("")).Error().To(HaveOccurred())
		})

		It("returns the expected destination", func() {
			Expect(Successful(whfs().Lstat(testdataPath("subdir/linky")))).To(And(
				// looking at dirFS.ReadLink
				// (https://cs.opensource.google/go/go/+/refs/tags/go1.27.0:src/os/file.go;l=837)
				// the result of reading the link verbatim...
				HaveField("Name()", "linky"),
				HaveField("Mode()", fs.ModeSymlink+0777),
			))
		})

	})

})
