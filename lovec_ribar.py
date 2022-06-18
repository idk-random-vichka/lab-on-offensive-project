### IMPORTS ###

from playsound import playsound
import time

# import other files from project
import spoofing_tool as spoof


### FUNCTIONS ###

# Function that runs the lovec_ribar attack
def lovec_ribar():
    # clear the terminal and print the intro message of the attack
    spoof.clear()
    print(open('resources/lovec_attack_intro.txt', 'r').read())
    time.sleep(2)

    # print the image of the attack
    lovec_image = open('resources/lovec_ribar.txt', 'r')
    lovec_image_contents = lovec_image.read()
    print(lovec_image_contents)

    # print the link to the youtube video
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')

    # play the sound
    # playsound('resources/lovec_ribar.mp3')

    # when the sound is over print the image and yt link again
    spoof.clear()
    print(lovec_image_contents)
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')
    print('https://www.youtube.com/watch?v=VfzILqHfg6U ;)')

    # wait thirty seconds before closing
    time.sleep(30)