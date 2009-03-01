# Copyright 1999-2008 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

inherit eutils

DESCRIPTION=""
HOMEPAGE="http://ati.amd.com/technology/streamcomputing/"
BASE_URI="http://a248.e.akamai.net/f/674/9206/0/www2.ati.com/sdkdwnld"
SRC_URI="amd64? ( ${BASE_URI}/amdstream-${PV}-lnx64.tar.gzip ) 
         x86? ( ${BASE_URI}/amdstream-${PV}-lnx32.tar.gzip )"

LICENSE=""
SLOT="0"
KEYWORDS="~amd64 ~x86"

DEPEND="
	=dev-libs/amd-stream-cal-1.3*
	"
RDEPEND=""

BROOKROOT="/usr/local/amdbrook"

src_unpack() {
	tar xvf ${DISTDIR}/${A} -C ${WORKDIR}
	cd ${WORKDIR}

	if use x86; then
		BIT_VERSION="i386"
	else
		BIT_VERSION="x86_64"
	fi
		
	einfo "Unpacking AMD-Brook"
	dd if=${WORKDIR}/amdstream-brook-${PV}.${BIT_VERSION}.run of=${WORKDIR}/amdbrook.tar.gz bs=1 skip=16384 >& /dev/null

	einfo "Extracting tar files"
	tar xvf amdbrook.tar.gz >& /dev/null
	
	einfo "Converting rpm to tar"
	rpm2tar amdstream-brook-${PV}-1.${BIT_VERSION}.rpm

	tar xvf ${WORKDIR}/amdstream-brook-${PV}-1.${BIT_VERSION}.tar >& /dev/null
}

src_compile() {
	cd "${WORKDIR}/${BROOKROOT}/platform"
	emake -j1 RELEASE="true" CALROOT="/usr/local/amdcal" || die "make platform failed"
}

src_install() {
	dodir "${BROOKROOT}"
	
	insinto "/usr/include/brook/"
	doins "${WORKDIR}/${BROOKROOT}/sdk/include/brook"/*.h* \
				|| die "Headers copy failed"
	insinto "/usr/include/brook/CPU/"
	doins "${WORKDIR}/${BROOKROOT}/sdk/include/brook/CPU"/* \
				|| die "Headers copy failed"

	dobin "${WORKDIR}/${BROOKROOT}/sdk/bin"/* \
				|| die "Bin creation filed"
	dolib.so "${WORKDIR}/${BROOKROOT}/sdk/lib"/* \
				|| die "Lib creation filed"
}
