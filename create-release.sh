#cvs -z3 -d:ext:hoganrobert@tork.cvs.sourceforge.net:/cvsroot/tork
# import -m "Initial Load" torsocks hoganrobert initial

export CVS_RSH=ssh
export VN=1.0-alpha
export VER=torsocks-$VN
export TAG=v1_0_alpha
cd ..
TOPDIR=$PWD
mkdir TorsocksReleases
cd TorsocksReleases
INSTALLDIR=$PWD

#create source package
cvs -z3 -d:ext:hoganrobert@tork.cvs.sourceforge.net:/cvsroot/tork export -r $TAG torsocks
cd torsocks
make -f Makefile.cvs
rm -rf autom4te.cache
cd ..
mv torsocks $VER
tar jcvf $VER.tar.bz2 $VER
tar zcvf $VER.tar.gz $VER
gpg -sba $VER.tar.bz2
gpg -sba $VER.tar.gz