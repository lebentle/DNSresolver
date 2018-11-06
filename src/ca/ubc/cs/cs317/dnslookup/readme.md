// README //
A few assumptions we made throughout this assignment include.

Assumptions
1. If we recieve a SocketTimeOutException we try to resend the packet. 
    However, if we get an IO Exception we exit the Program with an error. 

2. If the RCode Returned by A Response is not 0. We returned a error and do not
   try to resend the Packet. This contradicts the adsf example lookup trace, but 
   is consistent with the Assignment 2 specifications. 

