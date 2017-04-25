
u5: Project.cpp
	g++ -g Project_10_newest.cpp frameio2.cpp util.cpp checksum.cpp -lpthread -o out

u3: example1_3.cpp
	g++ -g example1_3.cpp frameio2.cpp util.cpp checksum.cpp -lpthread -o out
	./out
default: example1.cpp
	g++ -g example1.cpp frameio2.cpp util.cpp -lpthread -o out
	./out
