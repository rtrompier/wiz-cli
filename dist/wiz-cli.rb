# Fill the version, URLs, and SHA256 values after the first release is published.
class WizCli < Formula
  desc "CLI for the Wiz GraphQL API"
  homepage "https://github.com/rtrompier/wiz-cli"
  version "VERSION_PLACEHOLDER"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/rtrompier/wiz-cli/releases/download/vVERSION_PLACEHOLDER/wiz-cli-vVERSION_PLACEHOLDER-aarch64-apple-darwin.tar.gz"
      sha256 "SHA256_AARCH64_APPLE_DARWIN_PLACEHOLDER"
    else
      url "https://github.com/rtrompier/wiz-cli/releases/download/vVERSION_PLACEHOLDER/wiz-cli-vVERSION_PLACEHOLDER-x86_64-apple-darwin.tar.gz"
      sha256 "SHA256_X86_64_APPLE_DARWIN_PLACEHOLDER"
    end
  end

  on_linux do
    url "https://github.com/rtrompier/wiz-cli/releases/download/vVERSION_PLACEHOLDER/wiz-cli-vVERSION_PLACEHOLDER-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "SHA256_X86_64_UNKNOWN_LINUX_GNU_PLACEHOLDER"
  end

  def install
    bin.install "wiz-cli"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/wiz-cli --version")
  end
end
