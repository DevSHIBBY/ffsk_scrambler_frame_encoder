# ffsk_scrambler_frame_encoder
ATR 425 DIAMANT scrambled transmission FFSK signaling frame and CRC encoder


# What is it for?
This piece of code is used to check the FFSK data frame's integrity.
It is made to make sure your own FFSK encoder will generate a frame content that can be decoded by the a transceiver that operates with the genuine firmware.

# How to use it?
First of all, you need to ba able to capture FFSK frames. In the following example, I use a logic analyzer : 

![Picture of the ATR 425 DIAMANT logic board with logic analyzer probes attached to it](https://github.com/DevSHIBBY/ffsk_scrambler_frame_decoder/blob/main/documentation/probes_on_board.jpg)

The most import thing here are the probes attached to the FX419J pins 3 (TX clock) and 6 (TX data).

The captured frame can then be decoded using a synchronous decoder :

![Logic analyzer captured data](https://github.com/DevSHIBBY/ffsk_scrambler_frame_decoder/blob/main/documentation/logic_analyzer_capture.png)

Open the decoder with the following command :
```
python ffsk_scrambler_frame_encoder.py
```

Enter the **CLE** and **ID** parameters in the input boxes then click **Valider** : 

![Encoder screenshot](https://github.com/DevSHIBBY/ffsk_scrambler_frame_encoder/blob/main/documentation/encoder.png)

The full frame is generated with the 17-bit CRC.
The given data frame must match the transmitted one.
