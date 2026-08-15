class Agentgate < Formula
  desc "Firewall for AI coding agents — intercepts Bash/Read/Write/Edit, blocks outbound HTTP, asks humans via Slack/Telegram"
  homepage "https://github.com/FelixMa01/agentgate"
  url "https://github.com/FelixMa01/agentgate/archive/refs/tags/v0.14.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_OF_TARBALL"
  license "Apache-2.0"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    system bin/"agentgate", "--version"
    system bin/"agentgate", "doctor"
  end
end