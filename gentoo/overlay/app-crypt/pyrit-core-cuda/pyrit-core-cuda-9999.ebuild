inherit eutils python distutils subversion
DESCRIPTION="CPyrit-CUDA"
HOMEPAGE="http://code.google.com/p/pyrit/"
ESVN_REPO_URI="http://pyrit.googlecode.com/svn/trunk/cpyrit_cuda"

LICENSE="GPL-3"
KEYWORDS="~amd64 ~x86 ~x86-fbsd"
SLOT="0"
DEPEND="x11-drivers/nvidia-drivers
	dev-util/nvidia-cuda-toolkit
	dev-lang/python
	dev-libs/openssl"
RDEPEND="${DEPEND}"
