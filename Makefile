PROJECT_DIR := $(shell pwd)
PROM = wlan_station 
OBJ =  wpa_ctrl.o \
	wpamanager.o \
	main.o \
	utils/os_unix.o 

$(PROM): $(OBJ)
	$(CXX) -o $(PROM) $(OBJ) $(CFLAGS) -lpthread

%.o: %.c
	$(CXX) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf $(OBJ) $(PROM)

install:
	sudo install -D -m 755 $(PROM) -t /usr/bin/
