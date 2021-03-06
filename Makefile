
CXX := g++
CXXFLAGS += -I. -std=c++11
LDFLAGS  +=

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

install:
	sudo cp $(TARGET) /usr/local/bin

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

