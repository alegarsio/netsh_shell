import socket
from colorama import Back , Fore , Style
import colorama
colorama.init(autoreset=True)
import sys

print(Fore.LIGHTYELLOW_EX + f"""
                                                      
     o           o                o              ((  o  ))           https://github.com/alegarsio
    <|\        <|>               <|>                <|>                            
    / \\o      / \               < >                / >               Address : {socket.gethostbyname(socket.gethostname())} 
    \o/ v\     \o/    o__  __o    |          __o__  \o__ __o                    
    |   <\     |    /v      |>   o__/_     />  \    |     v\         OS : {sys.platform}           
    / \    \o  / \  />      //    |         \o      / \     <\                      
    \o/     v\ \o/  \o    o/      |          v\     \o/     o/                  
    |       <\ |    v\  /v __o   o           <\     |     <|                   
    / \        < \    <\/> __/>   <\__   _\o__</    / \    / \                  

      
    {Fore.LIGHTRED_EX}Warning Use this software without permission is ilegal

                 
""")