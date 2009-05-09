# Make tag:
# svn copy https://torsocks.googlecode.com/svn/trunk \
#          https://torsocks.googlecode.com/svn/tags/v1_0_gamma \
#          -m "tag for torsocks release v1.0 gamma"

export VN=1.0-gamma
export VER=torsocks-$VN
export TAG=v1_0_gamma
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