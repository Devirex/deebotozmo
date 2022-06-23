import asyncio
from crypt import crypt
import uuid, base64
from cryptography.fernet import Fernet
import cryptography
import debugpy
from Deebotozmo.deebotozmo.ecovacs_api import EcovacsAPI
from Deebotozmo.deebotozmo.ecovacs_mqtt import EcovacsMqtt
from Deebotozmo.deebotozmo.events import BatteryEvent
import aiohttp
from aiohttp import ClientError
from Deebotozmo.deebotozmo.util import md5
from Deebotozmo.deebotozmo.vacuum_bot import VacuumBot
debugpy.listen(("192.168.1.50",5678))

from .. import fhem
from .. import generic

class deebotozmo(generic.FhemModule):
    def __init__(self, logger):
        super().__init__(logger)

        attr_config = {
            "interval": {
                "default": 100,
                "format": "int",
                "help": "Change interval, default is 100.",
            }
        }
        self.set_attr_config(attr_config)

        set_config = {
            "login": {
                "args": ["username", "password"],
                "params": {
                    "username": {"default":"username", "format": "string"},
                    "password": {"default":"password", "format": "string"}   
                }
            },
            "readpass":{},
            "mode": {
                "args": ["mode"],
                "argsh": ["mode"],
                "params": {"mode": {"default": "eco", "optional": False}},
                "options": "eco,comfort",
            },
            "desiredTemp": {"args": ["temperature"], "options": "slider,10,1,30"},
            "holidayMode": {
                "args": ["endday", "endtime", "temperature"],
                "params": {
                    "endday": {"default": "31.12.2030"},
                    "endtime": {"default": "23:59"},
                    "temperature": {"default": 21, "format": "int"},
                },
            },
            "on": {
                "args": ["seconds"],
                "params": {
                    "seconds": {"default": 0, "optional": True, "format": "int"}
                },
                "help": "Specify seconds as parameter to change to off after X seconds.",
            },
            "off": {},
        }
        self.set_set_config(set_config)
        self.cipher_suite = Fernet(base64.urlsafe_b64encode(uuid.UUID(int=uuid.getnode()).bytes * 2))
    
    # FHEM FUNCTION
    async def Define(self, hash, args, argsh):
        await super().Define(hash, args, argsh)
        if len(args) > 3:
            return "Usage: define vacuumcleaner fhempy deebotozmo"
        await fhem.readingsBeginUpdate(hash)
        await fhem.readingsBulkUpdateIfChanged(hash, "state", "on")
        await fhem.readingsEndUpdate(hash, 1)

    async def set_login(self, hash, params):
        # user can specify mode as mode=eco or just eco as argument
        # params['mode'] contains the mode provided by user
        password = params["password"]
        username = params["username"]
        ciphered_text = await self.write_password(hash,password.encode()) 
        await fhem.readingsSingleUpdate(hash, "username", username, 1)
        
    async def set_readpass(self, hash, params):
        try: 
            pw = await self.read_password(hash)
        except (cryptography.fernet.InvalidToken):
             return "Unable to read stored password. Set login credentials again!"

    async def write_password(self, hash, password):
        # no params argument here, as set_off doesn't have arguments defined in set_list_conf
        ciphered_text = self.cipher_suite.encrypt(password)
        with open(hash['NAME'] + ".pw", 'wb') as file_object:  file_object.write(ciphered_text)
        return ciphered_text

    async def read_password(self, hash):
        # no params argument here, as set_off doesn't have arguments defined in set_list_conf
        with open(hash['NAME'] + ".pw", 'rb') as file_object:
            for line in file_object:
                encryptedpwd = line
        uncipher_text = (self.cipher_suite.decrypt(encryptedpwd))
        password = bytes(uncipher_text).decode("utf-8") #convert to string
        return password          
    
    async def main(self, hash):
        email = self.params["username"]
        password_hash = md5(self.read_password(self, hash))
        continent = "eu"
        country = "de"

        async with aiohttp.ClientSession() as session:
            api = EcovacsAPI(session, 0, email , password_hash , continent=continent, country=country,
                        verify_ssl=False)
            await api.login() 
            devices_ = await api.get_devices()   

            auth = await api.get_request_auth()
            bot = VacuumBot(session, auth, devices_[0], continent=continent, country=country, verify_ssl=False)
            mqtt = EcovacsMqtt(continent=continent, country=country)
            await mqtt.initialize(auth)
            await mqtt.subscribe(bot)

            async def on_battery(event: BatteryEvent):
                # Do stuff on battery event
                # Battery full
                await fhem.readingsSingleUpdate(hash, "Battery", event.value , 1)
                pass
            
            bot.events.battery.subscribe(on_battery)

    async def setup_deebootozmo(self, hash):
        loop = asyncio.get_event_loop()
        loop.create_task(self.main(self, hash))
        loop.run_forever()

    # Attribute function format: set_attr_NAMEOFATTRIBUTE(self, hash)
    # self._attr_NAMEOFATTRIBUTE contains the new state
    async def set_attr_interval(self, hash):
        # attribute was set to self._attr_interval
        # you can use self._attr_interval already with the new variable
        pass

    # Set functions in format: set_NAMEOFSETFUNCTION(self, hash, params)
    async def set_on(self, hash, params):
        # params contains the keyword which was defined in set_list_conf for "on"
        # if not provided by the user it will be "" as defined in set_list_conf (default = "" and optional = True)
        seconds = params["seconds"]
        if seconds != 0:
            await fhem.readingsSingleUpdate(hash, "state", "on " + str(seconds), 1)
        else:
            await fhem.readingsSingleUpdate(hash, "state", "on", 1)

    async def set_off(self, hash, params):
        # no params argument here, as set_off doesn't have arguments defined in set_list_conf
        await fhem.readingsSingleUpdate(hash, "state", "off", 1)
        self.create_async_task(self.long_running_task())
        return ""

    async def long_running_task(self):
        await asyncio.sleep(30)
        await fhem.readingsSingleUpdate(self.hash, "state", "long running off", 1)

    async def set_mode(self, hash, params):
        # user can specify mode as mode=eco or just eco as argument
        # params['mode'] contains the mode provided by user
        mode = params["mode"]
        await fhem.readingsSingleUpdate(hash, "mode", mode, 1)

    async def set_desiredTemp(self, hash, params):
        temp = params["temperature"]
        await fhem.readingsSingleUpdate(hash, "mode", temp, 1)

    async def set_holidayMode(self, hash, params):
        start = params["start"]
        end = params["end"]
        temp = params["temperature"]
        await fhem.readingsSingleUpdate(hash, "start", start, 1)
        await fhem.readingsSingleUpdate(hash, "end", end, 1)
        await fhem.readingsSingleUpdate(hash, "temp", temp, 1)

    