msg = "ABC" * 50000  # large payload
from stegano import lsb
lsb.hide("Elephant.png", msg).save("Elephant_stego_high.png")