import os
import asyncio
import re
import sys
from concurrent.futures import ThreadPoolExecutor,as_completed
import time
import httpx
import IPy
from tld import get_tld
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType

# 移除默认的处理器，添加新的处理器并设置级别
logger.remove()
logger.add(sink=sys.stderr, level="ERROR")

class ChinaDomain(object):
    def __init__(self, fileName, url):
        self.__fileName = fileName
        self.__url = url
        self.fullSet = set()
        self.domainSet = set()
        self.regexpSet = set()
        self.keywordSet = set()
        
        # 使用错误重试机制
        max_retries = 3
        for _ in range(max_retries):
            try:
                self.__update()
                self.__resolve()
                break
            except Exception as e:
                logger.error(f"Attempt failed: {e}")
                time.sleep(1)  # 重试前等待

    def __update(self):
        try:
            # 安全删除文件
            if os.path.exists(self.__fileName):
                try:
                    os.remove(self.__fileName)
                except OSError as e:
                    logger.error(f"Error removing file {self.__fileName}: {e}")
                    return
            
            # 添加超时和重试机制
            timeout = httpx.Timeout(10.0)
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            
            with httpx.Client(timeout=timeout, limits=limits) as client:
                response = client.get(self.__url)
                response.raise_for_status()
                
                # 使用临时文件避免写入失败导致文件损坏
                temp_file = f"{self.__fileName}.tmp"
                with open(temp_file, 'wb') as f:
                    f.write(response.content)
                os.rename(temp_file, self.__fileName)
                
        except httpx.RequestError as e:
            logger.error(f"Request failed: {e}")
        except Exception as e:
            logger.error(f"Update failed: {e}")

    def __isDomain(self, address):
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            return res.fld, res.subdomain
        except Exception:
            logger.warning(f"{address}: not domain")
            return '', ''

    def __resolve(self):
        if not os.path.exists(self.__fileName):
            logger.error(f"File not found: {self.__fileName}")
            return

        try:
            # 使用批处理来处理大文件
            batch_size = 1000
            current_batch = []
            
            with open(self.__fileName, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # 处理注释
                    if '#' in line:
                        line = line[:line.find('#')].strip()
                    
                    # 处理不同类型的规则
                    if line.startswith('regexp:'):
                        self.regexpSet.add(line[7:])
                    elif line.startswith('keyword:'):
                        self.keywordSet.add(line[8:])
                    else:
                        if line.startswith('full:'):
                            domain = line[5:]
                        elif line.startswith('domain:'):
                            domain = line[7:]
                        else:
                            domain = line
                            
                        current_batch.append(domain)
                        
                        # 批量处理域名
                        if len(current_batch) >= batch_size:
                            self.__process_domain_batch(current_batch)
                            current_batch = []
                
                # 处理最后一批
                if current_batch:
                    self.__process_domain_batch(current_batch)
                    
        except Exception as e:
            logger.error(f"Resolve failed: {e}")

    def __process_domain_batch(self, domains):
        for domain in domains:
            fld, subdomain = self.__isDomain(domain)
            if fld:
                if subdomain:
                    self.fullSet.add(domain)
                else:
                    self.domainSet.add(domain)
            else:
                logger.warning(f"{domain}: not domain[domain]")


class BlackList(object):
    def __init__(self):
        self.__ChinalistFile = os.getcwd() + "/rules/china.txt"
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/domain.txt"
        self.__domainlistFile_CN = os.getcwd() + "/rules/direct-list.txt"
        self.__domainlistUrl_CN = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/direct-list.txt"
        self.__domainlistFile_CN_Apple = os.getcwd() + "/rules/apple-cn.txt"
        self.__domainlistUrl_CN_Apple = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/apple-cn.txt"
        self.__domainlistFile_CN_Google = os.getcwd() + "/rules/google-cn.txt"
        self.__domainlistUrl_CN_Google = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/google-cn.txt"
        self.__iplistFile_CN = os.getcwd() + "/rules/CN-ip-cidr.txt"
        self.__iplistUrl_CN = "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/refs/heads/release/CN-ip-cidr.txt"
        self.__maxTask = 500

    def __getDomainList(self):
        logger.info("resolve adblock dns backup...")
        domainList = []
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r') as f:
                    tmp = f.readlines()
                    domainList = list(map(lambda x: x.replace("\n", ""), tmp))
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("adblock dns backup: %d"%(len(domainList)))
            return domainList
        
    def __getDomainSet_CN(self):
        logger.info("resolve China domain list...")
        fullSet,domainSet,regexpSet,keywordSet = set(),set(),set(),set()
        try:
            domain_cn = ChinaDomain(self.__domainlistFile_CN, self.__domainlistUrl_CN)
            domain_apple = ChinaDomain(self.__domainlistFile_CN_Apple, self.__domainlistUrl_CN_Apple)
            domain_google = ChinaDomain(self.__domainlistFile_CN_Google, self.__domainlistUrl_CN_Google)

            fullSet = domain_cn.fullSet | domain_apple.fullSet | domain_google.fullSet
            domainSet = domain_cn.domainSet | domain_apple.domainSet | domain_google.domainSet
            regexpSet = domain_cn.regexpSet | domain_apple.regexpSet | domain_google.regexpSet
            keywordSet = domain_cn.keywordSet | domain_apple.keywordSet | domain_google.keywordSet
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("China domain list: full[%d], domain[%d], regexp[%d], keyword[%d]"%(len(fullSet),len(domainSet),len(regexpSet),len(keywordSet)))
            return fullSet,domainSet,regexpSet,keywordSet
        
    def __getIPDict_CN(self):
        logger.info("resolve China IP list...")
        IPDict = dict()
        try:
            if os.path.exists(self.__iplistFile_CN):
                os.remove(self.__iplistFile_CN)
            
            with httpx.Client() as client:
                response = client.get(self.__iplistUrl_CN)
                response.raise_for_status()
                with open(self.__iplistFile_CN,'wb') as f:
                    f.write(response.content)
            
            if os.path.exists(self.__iplistFile_CN):
                with open(self.__iplistFile_CN, 'r') as f:
                    for line in f.readlines():
                        row = line.replace("\n", "").split("/")
                        ip, offset = row[0], int(row[1])
                        IPDict[IPy.parseAddress(ip)[0]] = offset
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("China IP list: %d"%(len(IPDict)))
            return IPDict
    
    async def __resolve(self, dnsresolver, domain):
        ipList = []
        try:
            # 添加超时控制
            async with asyncio.timeout(5):  # 5秒超时
                query_object = await dnsresolver.resolve(qname=domain, rdtype="A")
                query_item = None
                for item in query_object.response.answer:
                    if item.rdtype == DNSRdataType.A:
                        query_item = item
                        break
                if query_item is None:
                    raise Exception("not A type")
                for item in query_item:
                    ip = '{}'.format(item)
                    if ip != "0.0.0.0":
                        ipList.append(ip)
        except asyncio.TimeoutError:
            logger.warning(f'"{domain}": DNS resolution timeout')
        except Exception as e:
            logger.warning('"%s": %s' % (domain, e if e else "Resolver failed"))
        finally:
            return ipList

    async def __pingx(self, dnsresolver, domain, semaphore):
        async with semaphore:
            host = domain
            port = None
            ipList = []
            if domain.rfind(":") > 0:
                offset = domain.rfind(":")
                host = domain[ : offset]
                port = int(domain[offset + 1 : ])
            
            try:
                get_tld(host, fix_protocol=True, as_object=True)
            except Exception as e:
                port = 80

            if port:
                try:
                    async with asyncio.timeout(5):  # 添加超时控制
                        _, writer = await asyncio.open_connection(host, port)
                        writer.close()
                        await writer.wait_closed()
                        ipList.append(host)
                except Exception as e:
                    if port == 80:
                        port = 443
                        try:
                            async with asyncio.timeout(5):  # 添加超时控制
                                _, writer = await asyncio.open_connection(host, port)
                                writer.close()
                                await writer.wait_closed()
                                ipList.append(host)
                        except Exception as e:
                            logger.warning('"%s": %s' % (domain, e if e else "Connect failed"))
            else:
                count = 3
                while len(ipList) < 1 and count > 0:
                    ipList = await self.__resolve(dnsresolver, host)
                    count -= 1
                    if count > 0 and not ipList:
                        await asyncio.sleep(1)  # 添加重试延迟

            logger.info("%s: %s" % (domain, ipList))
            return domain, ipList

    def __generateBlackList(self, blackList):
        logger.info("generate black list...")
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(self.__blacklistFile, "w") as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
            logger.info("block domain: %d"%(len(blackList)))
        except Exception as e:
            logger.error("%s"%(e))
    
    def __generateChinaList(self, ChinaList):
        logger.info("generate China list...")
        try:
            if os.path.exists(self.__ChinalistFile):
                os.remove(self.__ChinalistFile)
            
            with open(self.__ChinalistFile, "w") as f:
                for domain in ChinaList:
                    f.write("%s\n"%(domain))
            logger.info("China domain: %d"%(len(ChinaList)))
        except Exception as e:
            logger.error("%s"%(e))

    def __testDomain(self, domainList, nameservers, port=53):
        logger.info("resolve domain...")
        dnsresolver = DNSResolver()
        dnsresolver.nameservers = nameservers
        dnsresolver.port = port
        
        async def run_tasks():
            semaphore = asyncio.Semaphore(self.__maxTask)
            tasks = [self.__pingx(dnsresolver, domain, semaphore) for domain in domainList]
            
            # 使用gather替代wait，支持取消操作
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                return {domain: ipList for domain, ipList in results if isinstance(results, tuple)}
            except asyncio.CancelledError:
                logger.warning("Domain resolution cancelled")
                return {}

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            domainDict = loop.run_until_complete(run_tasks())
        except Exception as e:
            logger.error(f"Error during domain resolution: {e}")
            domainDict = {}
        finally:
            loop.close()

        logger.info("resolve domain: %d"%(len(domainDict)))
        return domainDict

    def __isChinaDomain(self, domain, ipList, fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN, IPDict_CN):
        isChinaDomain = False
        domain_without_port = domain.split(':')[0]  # 更简洁的端口分离
        
        try:
            # 域名检查
            res = get_tld(domain_without_port, fix_protocol=True, as_object=True)
            
            # 按优先级和性能消耗依次检查
            if domain_without_port.endswith('.cn'):  # 使用endswith更高效
                return domain, True
                
            if domain_without_port in fullSet_CN:
                return domain, True
                
            if res.fld in domainSet_CN:
                return domain, True
                
            # 正则和关键词匹配合并处理，避免重复break
            for regexp in regexpSet_CN:
                if re.match(regexp, domain_without_port):
                    return domain, True
                    
            for keyword in keywordSet_CN:
                if keyword in domain_without_port:  # 简单字符串匹配比正则更快
                    return domain, True
            
            # IP检查
            if ipList:
                for ip in ipList:
                    try:
                        ip_int = IPy.parseAddress(ip)[0]
                        for network, bits in IPDict_CN.items():
                            if (ip_int ^ network) >> (32 - bits) == 0:
                                return domain, True
                    except Exception as e:
                        logger.debug(f'IP parse error for {ip}: {e}')
                        continue
                        
        except Exception as e:
            logger.warning(f'Domain check error for "{domain}": {str(e)}')
        
        return domain, False

    def generate(self):
        try:
            domainList = self.__getDomainList()
            if not domainList:
                logger.warning("No domains to process")
                return

            domainDict = self.__testDomain(domainList, ["127.0.0.1"], 5053)
            
            # 预检查必要条件
            fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN = self.__getDomainSet_CN()
            IPDict_CN = self.__getIPDict_CN()
            
            if len(domainSet_CN) <= 100 or len(IPDict_CN) <= 100:
                logger.error("Insufficient CN domain or IP data")
                return
                
            # 使用线程池处理域名检查
            blackList = []
            ChinaList = []
            
            # 优化线程池配置
            max_workers = min(32, max(4, os.cpu_count() * 2))  # 限制最大线程数
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_domain = {}
                
                # 提交任务
                for domain in domainList:
                    if domainDict.get(domain):
                        future = executor.submit(
                            self.__isChinaDomain,
                            domain,
                            domainDict[domain],
                            fullSet_CN,
                            domainSet_CN,
                            regexpSet_CN,
                            keywordSet_CN,
                            IPDict_CN
                        )
                        future_to_domain[future] = domain
                    else:
                        blackList.append(domain)
                
                # 收集结果
                for future in as_completed(future_to_domain):
                    try:
                        domain, isChinaDomain = future.result()
                        if isChinaDomain:
                            ChinaList.append(domain)
                    except Exception as e:
                        logger.error(f"Error processing domain {future_to_domain[future]}: {e}")
                        blackList.append(future_to_domain[future])
            
            # 生成列表文件
            if ChinaList:
                self.__generateChinaList(ChinaList)
            if blackList:
                self.__generateBlackList(blackList)
                
        except Exception as e:
            logger.error(f"Generation process failed: {e}")
            raise  # 重新抛出异常，让上层处理

if __name__ == "__main__":
    '''
    # for test
    logFile = os.getcwd() + "/adblock.log"
    if os.path.exists(logFile):
        os.remove(logFile)
    logger.add(logFile)
    '''
    blackList = BlackList()
    blackList.generate()
