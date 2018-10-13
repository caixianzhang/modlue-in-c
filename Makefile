CXX = gcc
CXXFLAGS = -O2 -g -Wall
LDFLAGS = -lpthread

OBJS = main.o net.o threadpool.o

TARGET = module

$(TARGET):$(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@rm -rf *.o

.PHONY:clean
clean:
	rm -rf *.o $(TARGET)