class Leaktor < Formula
  desc "Blazingly fast secrets scanner with validation capabilities"
  homepage "https://github.com/reschjonas/leaktor"
  url "https://github.com/reschjonas/leaktor/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "" # Will be filled automatically on release
  license "MIT"
  head "https://github.com/reschjonas/leaktor.git", branch: "master"

  depends_on "rust" => :build
  depends_on "pkg-config" => :build
  depends_on "openssl@3"

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "leaktor", shell_output("#{bin}/leaktor --version")

    # Create a test file with a fake secret
    (testpath/"test.txt").write("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")

    # Run leaktor scan
    output = shell_output("#{bin}/leaktor scan #{testpath} 2>&1")
    assert_match "AWS Access Key", output
  end
end
