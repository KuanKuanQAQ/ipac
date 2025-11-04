# clang++ -fPIC -shared -o /home/lrk/CRR/samples/log_time/FuncTimeLogger.so /home/lrk/CRR/samples/log_time/FuncTimeLogger.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core passes`

# Makefile for FuncTimeLogger LLVM pass plugin

# LLVM installation
LLVM_CONFIG := /usr/lib64/llvm15/bin/llvm-config

# Compiler and flags
CXX := clang++
CXXFLAGS := -fPIC -O2 `$(LLVM_CONFIG) --cxxflags`
LDFLAGS := -shared

# Source and target
SRC := FuncTimeLogger.cpp
TARGET := FuncTimeLogger.so

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)