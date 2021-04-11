import time
import re
import argparse
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from PrettyLogging import log

'''
    some global settings
'''
# for crawling headers
headers = {
    'User-Agent': 'MMozilla/5.0(Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0'
}

# for image link recognition
LINK_PATTERN = "FileSharing.action?hash=1" # normal link
MD_PATTERN = "evernotecid://"
MISSING_PATTERN = "ATTRNOTFOUND" # failed link: ATTRNOTFOUND, but still need to be counted

# for pretty logging
log.info("Welcome to EverNote Image Link Converter.")


'''
Real functions begin here
'''
def read_image_outer_link(share_url : str, wait_interval : int = 3) -> list:
    log.info("Begining extracting image link from the shared note...")
    log.info("Selenium Chrome Webdriver has been called")

    # selenium webdriver
    driver = webdriver.Chrome(ChromeDriverManager().install())
    driver.get(share_url)

    # force to sleep thus the image tags can appear
    log.debug("The program is going to waiting for %d seconds." % wait_interval)
    time.sleep(wait_interval)
    image_links = []
    for image in driver.find_elements_by_tag_name("img"):
        link = image.get_attribute("src")
        if LINK_PATTERN in link or MISSING_PATTERN in link: # make sure they are the right links
            image_links.append(link)
        else:
            log.warning("Encounter with unrecognized link and miss it: %s" % link)
    driver.quit()
    log.info("Extracting Links Done. There are %d image links." % len(image_links))
    return image_links


def clean_original_md(md_content : str) -> str:
    log.info("Begining cleaning the '\\' in your markdown file...") # evernote bug and have to deal with it
    for i, line in enumerate(md_content):
        if line[0] == '\\': # the odd evernote bug
            md_content[i] = line[1:]
    open("temp.md", "w").writelines(md_content)
    return md_content


def read_original_md(md_file : str) -> str:
    log.info("Begining reading your markdown file...")

    with open(md_file, "r") as f:
        content = f.readlines()
    clean_content = clean_original_md(content)
    log.info("Your makdown file has been read in and ready.")
    return clean_content


def check_link_matched(outer_num : int, md_content : str) -> bool:
    md_num = sum(MD_PATTERN in link for link in md_content)
    return md_num == outer_num


def image_link_replace(md_content : str, image_links : list, new_md : str) -> bool:
    log.info("Begining replacing the evernotecid link with outer link...")    
    log.info("Checking if the link numbers are matched...")
    if not check_link_matched(len(image_links), md_content):
        log.error("The number between outer links and markdown links are not equal. Please check again.")
        return False
    log.info("Link Number Check Passed.")
    log.info("Replacing...")
    cnt = 0
    for i, md_line in enumerate(md_content):
        candidate = re.findall(r'(?:!\[.*?\]\((.*?)\))', md_line) # extracting the markdown image link
        if len(candidate) and MD_PATTERN in candidate[0]:
            replaced = image_links[cnt]
            if MISSING_PATTERN in image_links[cnt]:
                replaced = "Your Image Link is not avaliable"
            md_content[i] = md_line.replace(candidate[0], replaced)
            cnt += 1
    log.info("Done Replacing and Saving New Markdown File.")
    open(new_md, "w").writelines(md_content)
    return True


if __name__ == "__main__":
    '''
    Some Args Setting; We can use -h to know how to use this script.
    '''
    parser = argparse.ArgumentParser(description='EverNote Markdown Image Link Converter')
    parser.add_argument("-l", "--link", help="your evernote shared web page link")
    parser.add_argument("-i", "--input", help="your markdown file copied from evernote")
    parser.add_argument("-o", "--output", help="converted markdown file")
    parser.add_argument("-t", "--time", help="sleeping inverval")

    args = parser.parse_args()
    
    share_url, md_file, new_md, wait_interval = args.link, args.input, args.output, int(args.time)
    if (not share_url) or (not md_file):
        log.critical("Your Note URL or Your Markdown File is Needed.")
        exit()
    if not new_md:
        new_md = "new.md"
    log.debug("Your evernote url is: ")
    print("\t", share_url)
    log.debug("Your markdown file to be converted is: ")
    print("\t", md_file)
    log.debug("Your new markdown file will be: ")
    print("\t", new_md)

    outer_links = read_image_outer_link(share_url, wait_interval)
    content = read_original_md(md_file)
    if not image_link_replace(content, outer_links, new_md):
        log.error("Something wrong. Please check your shared notes or markdown file.")
    