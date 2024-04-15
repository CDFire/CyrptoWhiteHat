COMMON := hmac_sha1.cpp powmod.cpp sha1.cpp aes.cpp 

atm: atm.cpp $(COMMON)
	g++ $^ -o ./atm

bank: bank.cpp $(COMMON)
	g++ $^ -o ./bank
