#cvs -z3 -d:ext:hoganrobert@tork.cvs.sourceforge.net:/cvsroot/tork
# import -m "Initial Load" torsocks hoganrobert initial

export VN=1.0-beta
export VER=torsocks-$VN
export TAG=v1_0_beta
cd ..
TOPDIR=$PWD
mkdir TorsocksReleases
cd TorsocksReleases

#create source package
svn export http://torsocks.googlecode.com/svn/tags/$TAG $TAG
cd $TAG
make -f Makefile.cvs
rm -rf autom4te.cache
cd ..
mv $TAG $VER
tar jcvf $VER.tar.bz2 $VER
tar zcvf $VER.tar.gz $VER
gpg -sba $VER.tar.bz2
gpg -sba $VER.tar.gz