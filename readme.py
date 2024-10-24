import re
import os
from typing import List

from loguru import logger

class Rule(object):
    def __init__(self, name:str, type:str, url:str, latest:str, update:bool=False):
        self.name = name
        self.filename = self.name.replace(' ', '_') + '.txt'
        self.type = type
        self.url = url
        self.latest = latest
        self.update = update

# redme文件操作
class ReadMe(object):
    def __init__(self, filename:str):
        self.filename = filename
        self.ruleList:List[Rule] = []

    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:].split('|')))
                    if rule[2].find('(') > 0 and rule[2].find(')') > 0 and len(rule) > 4:
                        url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                        matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                        if matchObj1:
                            self.ruleList.append(Rule(rule[0], rule[1], url, rule[4]))
        return self.ruleList
    
    def setRules(self, ruleList:List[Rule]):
        self.ruleList = ruleList
    
    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)
        
        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters\n")
            f.write("适用于AdGuard的去广告合并规则，每12个小时更新一次。\n")
            f.write("## 订阅链接\n")
            f.write("1. AdGuard Home 等DNS拦截服务使用规则1\n")
            f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2\n")
            f.write("3. 规则1’、规则2’为相应的 Lite 版，仅针对国内域名拦截\n\n")
            f.write("| 规则 | 原始链接 | 加速链接 | \n")
            f.write("|:-|:-|:-|\n")
            f.write("| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdns.txt)  |\n")
            f.write("| 规则1'：DNS 拦截 Lite | [原始链接](https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdnslite.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdnslite.txt) |\n")
            f.write("| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilters.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilters.txt) |\n")
            f.write("| 规则2'：插件拦截 Lite | [原始链接](https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilterslite.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilterslite.txt) |\n")
            f.write("## 规则源\n")
            f.write("\n")
            f.write("| 规则 | 类型 | 原始链接 | 加速链接 |  更新日期 |\n")
            f.write("|:-|:-|:-|:-|:-|\n")
            for rule in self.ruleList:
                f.write("| %s | %s | [原始链接](%s) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/%s.txt) | %s |\n" % (rule.name,rule.type,rule.url,rule.filename,rule.latest))
            f.write("\n")