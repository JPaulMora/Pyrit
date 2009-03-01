inherit eutils python distutils subversion
DESCRIPTION="CPyrit-Stream"
HOMEPAGE="http://code.google.com/p/pyrit/"
ESVN_REPO_URI="http://pyrit.googlecode.com/svn/trunk/cpyrit_stream"

LICENSE="GPL-3"
KEYWORDS="~amd64 ~x86 ~x86-fbsd"
SLOT="0"
DEPEND=">=dev-util/amd-stream-brook-1.3.0_beta
	dev-lang/python
	dev-libs/openssl
	<=x11-drivers/ati-drivers-9"
RDEPEND="${DEPEND}"
