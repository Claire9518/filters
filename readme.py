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
        self.proxyList = [
            "",
            "https://gcore.jsdelivr.net/gh",
            "https://github.boki.moe",
            "https://ghfast.top"
        ]
    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:-1].split('|')))
                    if rule[2].find('(') > 0 and rule[2].find(')') > 0 and rule[1].find('(') < 0:
                        url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                        matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                        if matchObj1:
                            self.ruleList.append(Rule(rule[0], rule[1], url, rule[-1]))
        return self.ruleList

    def getRulesNames(self) -> str:
        names = ""
        
        for rule in self.ruleList:
            names += rule.name + '、'
        
        return names[:-1]    
    def setRules(self, ruleList:List[Rule]):
        self.ruleList = ruleList

    def __subscribeLink(self, fileName:str, url:str=None):
        link = ""

        if url:
            link += " [原始链接](%s) |"%(url)
        else:
            link += " [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/%s) |"%(fileName)
        
        for i in range(1, len(self.proxyList)):
            proxy = self.proxyList[i]
            if proxy.startswith("https://gcore.jsdelivr.net/"):
                link += " [加速链接%d](%s/217heidai/adblockfilters@main/rules/%s) |"%(i, proxy, fileName)
            else:
                link += " [加速链接%d](%s/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/%s) |"%(i, proxy, fileName)
        
        return link
    
    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)
        
        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters\n")
            f.write("适用于AdGuard的去广告合并规则，每12个小时更新一次。\n")
            f.write("## 订阅链接\n")
            f.write("## 订阅链接\n")
            f.write("1. 规则x’为规则x的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）\n")
            f.write("2. 已对 jsdelivr(加速链接1) 缓存进行主动刷新，但仍存在一定刷新延时\n")
            f.write("3. AdGuard 等浏览器插件使用规则1 + 规则2（规则2为规则1的补充，仅适用浏览器插件）\n")
            f.write("\n")
            tmp = "| 规则 | 原始链接 |"
            for i in range(1, len(self.proxyList)):
                tmp += " 加速链接%d |"%(i)
            tmp += " 适配说明 |\n"
            f.write(tmp)
            tmp = "|" + ":-|" * ( 1 + len(self.proxyList) + 1) + "\n"
            f.write(tmp)
            f.write("| 规则1 |" + self.__subscribeLink("adblockdns.txt") + " AdGuard、AdGuard Home 等 |\n")
            f.write("| 规则1' |" + self.__subscribeLink("adblockdnslite.txt") + " AdGuard、AdGuard Home 等 |\n")
            f.write("| 规则2 |" + self.__subscribeLink("adblockfilters.txt") + " AdGuard 等 |\n")
            f.write("| 规则2' |" + self.__subscribeLink("adblockfilterslite.txt") + " AdGuard 等 |\n")
            f.write("| 规则3 |" + self.__subscribeLink("adblockdomain.txt") + " InviZible Pro、personalDNSfilter |\n")
            f.write("| 规则3' |" + self.__subscribeLink("adblockdomainlite.txt") + " InviZible Pro、personalDNSfilter |\n")
            f.write("| 规则4 |" + self.__subscribeLink("adblockdnsmasq.txt") + " DNSMasq |\n")
            f.write("| 规则4' |" + self.__subscribeLink("adblockdnsmasqlite.txt") + " DNSMasq |\n")
            f.write("| 规则5 |" + self.__subscribeLink("adblocksmartdns.conf") + " SmartDNS |\n")
            f.write("| 规则5' |" + self.__subscribeLink("adblocksmartdnslite.conf") + " SmartDNS |\n")
            f.write("| 规则6 |" + self.__subscribeLink("adblockclash.list") + " Shadowrocket |\n")
            f.write("| 规则6' |" + self.__subscribeLink("adblockclashlite.list") + " Shadowrocket |\n")
            f.write("| 规则7 |" + self.__subscribeLink("adblockqx.conf") + " QuantumultX |\n")
            f.write("| 规则7' |" + self.__subscribeLink("adblockqxlite.conf") + " QuantumultX |\n")
            f.write("| 规则8 |" + self.__subscribeLink("adblockmihomo.yaml") + " Clash Meta(Mihomo) yaml |\n")
            f.write("| 规则8' |" + self.__subscribeLink("adblockmihomolite.yaml") + " Clash Meta(Mihomo) yaml |\n")
            f.write("| 规则9 |" + self.__subscribeLink("adblockmihomo.mrs") + " Clash Meta(Mihomo) mrs |\n")
            f.write("| 规则9' |" + self.__subscribeLink("adblockmihomolite.mrs") + " Clash Meta(Mihomo) mrs |\n")
            f.write("| 规则10 |" + self.__subscribeLink("adblockhosts.txt") + " Hosts |\n")
            f.write("| 规则10' |" + self.__subscribeLink("adblockhostslite.txt") + " Hosts |\n")
            f.write("| 规则11 |" + self.__subscribeLink("adblocksingbox.json") + " sing-box 1.12.x json |\n")
            f.write("| 规则11' |" + self.__subscribeLink("adblocksingboxlite.json") + " sing-box 1.12.x json |\n")
            f.write("| 规则12 |" + self.__subscribeLink("adblocksingbox.srs") + " sing-box 1.12.x srs |\n")
            f.write("| 规则12' |" + self.__subscribeLink("adblocksingboxlite.srs") + " sing-box 1.12.x srs |\n")
            f.write("| 规则13 |" + self.__subscribeLink("adblockloon.list") + " Loon |\n")
            f.write("| 规则13' |" + self.__subscribeLink("adblockloonlite.list") + " Loon |\n")
            f.write("| 规则14 |" + self.__subscribeLink("adblocksurge.list") + " Surge |\n")
            f.write("| 规则14' |" + self.__subscribeLink("adblocksurgelite.list") + " Surge |\n")
            f.write("\n")
            f.write("## 规则源\n")
            f.write("\n")
            tmp = "| 规则 | 类型 | 原始链接 |"
            for i in range(1, len(self.proxyList)):
                tmp += " 加速链接%d |"%(i)
            tmp += " 更新日期 |\n"
            f.write(tmp)
            tmp = "|" + ":-|" * ( 2 + len(self.proxyList) + 1) + "\n"
            f.write(tmp)
            for rule in self.ruleList:
                f.write("| %s | %s |%s %s |\n" % (rule.name, rule.type, self.__subscribeLink(rule.filename, rule.url),rule.latest))
            f.write("\n")
            f.write("\n")
