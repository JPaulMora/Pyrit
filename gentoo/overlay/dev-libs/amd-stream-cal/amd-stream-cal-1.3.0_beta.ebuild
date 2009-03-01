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

DEPEND=""
RDEPEND="
	>=x11-drivers/ati-drivers-8.561
	virtual/libstdc++
	"
CALROOT="/usr/local/amdcal"

src_unpack() {
	tar xvf ${DISTDIR}/${A} -C ${WORKDIR}
	cd ${WORKDIR}

	if use x86; then
		BIT_VERSION="i386"
	else
		BIT_VERSION="x86_64"
	fi
		
	einfo "Unpacking AMD-Cal"
	dd if=${WORKDIR}/amdstream-cal-${PV}.${BIT_VERSION}.run of=${WORKDIR}/amdcal.tar.gz bs=1 skip=16384 >& /dev/null

	einfo "Extracting tar files"
	tar xvf amdcal.tar.gz >& /dev/null
	
	einfo "Converting rpm to tar"
	rpm2tar amdstream-cal-${PV}-1.${BIT_VERSION}.rpm

	einfo "Extracting files"
	tar xvf ${WORKDIR}/amdstream-cal-${PV}-1.${BIT_VERSION}.tar >& /dev/null
}

src_install() {
	dodir "${CALROOT}"

	insinto "/usr/include/amdcal/"
	doins "${WORKDIR}/${CALROOT}/include"/* \
				|| die "Include copy failed"
	
	insinto "${CALROOT}"
	dosym "/usr/include/amdcal" "${CALROOT}/include" \
				|| die "Symlink to includes failed"
}
