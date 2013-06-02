noinst_PROGRAMS= test_torsocks

test_torsocks_SOURCES= test_torsocks.c
test_torsocks_LDFLAGS= $(TESTLDFLAGS)

dist_data_DATA = run_tests.sh expectedresults.txt

check-am:
	./run_tests.sh
