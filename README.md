This is a program that sniffs packets on your network. 
You can choose what interface to sniff on, by inputing the number associated with each interface when the program prompts for your input.
NOTE: This program does not decode the layers, it "dumps" the raw hex bytes, then converts it to their equivalent
characters if and only if they are in the printable ascii range(prints out fullstop(.), if they are not.

NOTE: You have to have the necessary include files to be able to compile this code, 

Also to compile you need to link to pcap using the -l flag. 
Also you need root privieges to execute, cos of the library makes use of raw sockets to sniff. 

EXAMPLE:

gcc -g pcapnsniff.c -l pcap   --



sudo ./a.out     -- 
