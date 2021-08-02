import math

import re
import socket
import struct
import exceptions




#überprüft den Sheet-Name, wenn es einen Treffer gibt, dann For-Schleife Unterbrechung, liefer den Sheet-Name zurück
#wenn es keinen Treffer gibt, dann schreibt einen Nachricht in dem Logger und wirft eine Ausnahme