inherit eutils python distutils subversion
DESCRIPTION="Pyrit"
HOMEPAGE="http://code.google.com/p/pyrit/"
ESVN_REPO_URI="http://pyrit.googlecode.com/svn/trunk/pyrit"

LICENSE="GPL-3"
KEYWORDS="~amd64 ~x86 ~x86-fbsd"
IUSE="cuda stream"
SLOT="0"
DEPEND="stream? ( app-crypt/pyrit-core-stream )
	cuda? ( app-crypt/pyrit-core-cuda )
	dev-lang/python
	dev-libs/openssl"
RDEPEND="${DEPEND}"
