
CXX := g++
LIBSLANKDEV := $(HOME)/git/libslankdev
CXXFLAGS += -I. -I$(LIBSLANKDEV) -std=c++11
LDFLAGS  += -lpcap

TARGET = pktsend
SRCS = main.cc
OBJS = $(SRCS:.cc=.o)

.cc.o:
	@echo " CXX $@"
	@$(CXX) $(CXXFLAGS) -c $< -o $@


$(TARGET): $(OBJS)
	@echo " LD $@"
	@$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.out

run:
	@./pktsend


all:
	$(CXX) $(CXXFLAGS) main.cc $(LDFLAGS)

