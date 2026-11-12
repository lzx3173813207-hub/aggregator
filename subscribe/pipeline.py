# -*- coding: utf-8 -*-

import os
import random
import re
import subprocess
import time

import utils
import workflow
import yaml
from airport import AirPort
from config.models import GroupConfig, NodeInput, SiteConfig
from logger import logger
from origin import Origin
from workflow import TaskConfig, exists

import clash
import subconverter


def assign_sites(
    sites: list[SiteConfig],
    groups: dict[str, GroupConfig],
    retry: int,
    bin_name: str,
    allow_gmail_alias: bool = False,
    special_protocols: bool | None = None,
) -> tuple[list[TaskConfig], dict[str, list[int]]]:
    tasks, grouped = [], {}
    retry, globalid = max(1, retry), 0
    if special_protocols is None:
        special_protocols = AirPort.enable_special_protocols()

    for site in sites or []:
        if not isinstance(site, SiteConfig) or not site.enable:
            continue
        name = utils.trim(site.name).lower()
        domain = utils.trim(site.domain).lower()
        subscribe = site.nodes.subscribe_list()
        if len(subscribe) >= 2:
            subscribe = list(dict.fromkeys(subscribe))

        count = min(max(1, int(site.count)), 10)
        if subscribe:
            count = len(subscribe)
        if site.renew and site.renew.accounts:
            count = len(site.renew.accounts)

        source = site.origin
        if not source:
            source = Origin.TEMPORARY.name if not domain else Origin.OWNED.name
        site.origin = source
        if source != Origin.TEMPORARY.name:
            site.errors = max(site.errors, 0) + 1
        if name:
            site.name = name.rsplit("-", maxsplit=1)[0]

        if not name or (not domain and site.nodes.empty()) or count <= 0:
            continue

        if site.nodes.uris or site.nodes.proxies:
            globalid += 1
            task = TaskConfig(
                name=name,
                taskid=globalid,
                domain=domain,
                nodes=NodeInput(
                    subscribe=list(subscribe),
                    uris=list(site.nodes.uris),
                    proxies=list(site.nodes.proxies),
                ),
                index=-1,
                retry=retry,
                max_rate=site.max_rate,
                bin_name=bin_name,
                renew=(
                    site.renew.jobs(coupon=site.coupon, api_prefix=site.api_prefix)[0]
                    if site.renew and site.renew.accounts
                    else None
                ),
                rename=site.rename,
                exclude=site.exclude,
                include=site.include,
                check_alive=site.check_alive,
                coupon=site.coupon,
                require_tls=site.require_tls,
                ignore_default_exclude=site.ignore_default_exclude,
                allow_gmail_alias=allow_gmail_alias,
                skip_captcha=site.skip_captcha,
                special_protocols=special_protocols,
                invite_code=site.invite_code,
                api_prefix=site.api_prefix,
            )
            if not exists(tasks=tasks, task=task):
                tasks.append(task)
                for push_name in site.push_to:
                    grouped.setdefault(push_name, []).append(globalid)
            continue

        for index in range(count):
            globalid += 1
            sub = subscribe[index] if index < len(subscribe) else ""
            renew = None
            if site.renew:
                jobs = site.renew.jobs(coupon=site.coupon, api_prefix=site.api_prefix)
                if index < len(jobs):
                    renew = jobs[index]
            task = TaskConfig(
                name=name,
                taskid=globalid,
                domain=domain,
                nodes=NodeInput(subscribe=sub),
                index=-1 if count == 1 else index + 1,
                retry=retry,
                max_rate=site.max_rate,
                bin_name=bin_name,
                renew=renew,
                rename=site.rename,
                exclude=site.exclude,
                include=site.include,
                check_alive=site.check_alive,
                coupon=site.coupon,
                require_tls=site.require_tls,
                ignore_default_exclude=site.ignore_default_exclude,
                allow_gmail_alias=allow_gmail_alias,
                skip_captcha=site.skip_captcha,
                special_protocols=special_protocols,
                invite_code=site.invite_code,
                api_prefix=site.api_prefix,
            )
            if exists(tasks=tasks, task=task):
                continue
            tasks.append(task)
            for push_name in site.push_to:
                if push_name not in groups:
                    logger.error(f"cannot found push config, name=[{push_name}]\tsite=[{name}]")
                    continue
                grouped.setdefault(push_name, []).append(globalid)

    return tasks, grouped


def execute_tasks(tasks: list[TaskConfig]) -> list[tuple[int, list[dict[str, object]]]]:
    return utils.multi_process_run(func=workflow.executewrapper, tasks=tasks)


def check_alive_proxies(
    proxies: list[dict[str, object]],
    clash_bin: str,
    workspace: str,
    filename: str = "config.yaml",
    timeout: int = 5000,
    test_url: str = "https://www.google.com/generate_204",
    delay: int = 5000,
    num_threads: int = 64,
    display: bool = True,
    skip: bool = False,
    group: str = "",
) -> list[dict[str, object]]:
    if not proxies:
        return []

    proxies = clash.generate_config(workspace, proxies, filename)
    if skip:
        return proxies

    checks, nochecks = workflow.liveness_fillter(proxies=proxies)
    if not checks:
        return nochecks

    binpath = os.path.join(workspace, clash_bin)
    utils.chmod(binpath)

    checks = clash.generate_config(workspace, checks, filename)
    # patched: drop proxies that make clash refuse the whole config (one bad node would kill the run)
    for _ in range(200):
        try:
            test = subprocess.run(
                [binpath, "-t", "-d", workspace, "-f", os.path.join(workspace, filename)],
                capture_output=True, text=True, timeout=120,
            )
        except Exception as e:
            logger.error(f"clash config test error: {e}")
            break
        output = (test.stdout or "") + (test.stderr or "")
        if test.returncode == 0 or "test is successful" in output:
            break
        bad = re.search(r"proxy (\d+):", output)
        if not bad or int(bad.group(1)) >= len(checks):
            logger.error(f"clash config test failed and cannot locate bad proxy: {output[-300:]}")
            break
        index = int(bad.group(1))
        logger.warning(f"drop invalid proxy #{index}: {output.strip().splitlines()[-1][:200]}")
        checks.pop(index)
        checks = clash.generate_config(workspace, checks, filename)

    logger.info(f"startup clash now, workspace: {workspace}, config: {filename}")
    process = subprocess.Popen([binpath, "-d", workspace, "-f", os.path.join(workspace, filename)])
    logger.info(f"clash start success, begin check proxies, group: {group}\tcount: {len(checks)}")
    time.sleep(random.randint(5, 8))
    params = [
        [item, clash.EXTERNAL_CONTROLLER, timeout, test_url, delay, False] for item in checks if isinstance(item, dict)
    ]
    masks = utils.multi_thread_run(func=clash.check, tasks=params, num_threads=num_threads, show_progress=display)
    try:
        process.terminate()
    except Exception:
        logger.error(f"terminate clash process error, group: {group}")

    availables = [checks[i] for i in range(len(checks)) if masks[i]]
    # patched: plain http/socks proxies are not VPN nodes, drop them
    availables = [p for p in availables if str(p.get("type", "")).lower() not in ("http", "socks5", "socks")]
    # patched: keep every alive Asian node, then the fastest others, up to MAX_NODES in total
    try:
        cap = int(os.getenv("MAX_NODES", "500") or 0)
    except ValueError:
        cap = 500
    if cap > 0 and len(availables) > cap:
        asia = re.compile(
            r"香港|台湾|台灣|日本|新加坡|狮城|韩国|韓國|东京|大阪|首尔|🇭🇰|🇹🇼|🇯🇵|🇸🇬|🇰🇷|Hong ?Kong|Taiwan|Japan|Tokyo|Osaka|Singapore|Korea|Seoul|(?<![A-Za-z])(HK|TW|JP|SG|KR)(?![A-Za-z])",
            re.I,
        )
        speed = lambda p: clash.DELAYS.get(p.get("name", ""), 99999)
        first = sorted([p for p in availables if asia.search(str(p.get("name", "")))], key=speed)[:cap]
        rest = sorted([p for p in availables if not asia.search(str(p.get("name", "")))], key=speed)
        kept = first + rest[: max(0, cap - len(first))]
        logger.info(f"trim alive proxies to {len(kept)} (asia: {len(first)}) from {len(availables)}")
        availables = kept
    nochecks.extend(availables)
    logger.info(
        f"proxies check finished, total: {len(checks)}, alive: {len(availables)}, dead: {len(checks) - len(availables)}"
    )
    return nochecks


def convert_proxies(
    proxies: list[dict[str, object]],
    subconverter_bin: str,
    workspace: str,
    source_file: str,
    dest_file: str,
    artifact: str,
    target: str,
    emoji: bool = True,
    list_only: bool = True,
    ignore_exclude: bool = False,
) -> str:
    filepath = os.path.join(workspace, source_file)
    with open(filepath, "w+", encoding="utf8") as handle:
        yaml.add_representer(clash.QuotedStr, clash.quoted_scalar)
        yaml.dump({"proxies": proxies}, handle, allow_unicode=True)

    generate_conf = os.path.join(workspace, "generate.ini")
    if os.path.exists(generate_conf) and os.path.isfile(generate_conf):
        os.remove(generate_conf)

    success = subconverter.generate_conf(
        filepath=generate_conf,
        name=artifact,
        source=source_file,
        dest=dest_file,
        target=target,
        emoji=emoji,
        list_only=list_only,
        ignore_exclude=ignore_exclude,
    )
    if not success:
        return ""
    if not subconverter.convert(binname=subconverter_bin, artifact=artifact):
        return ""

    converted = os.path.join(workspace, dest_file)
    if not os.path.exists(converted) or not os.path.isfile(converted):
        return ""
    with open(converted, "r", encoding="utf8") as handle:
        return handle.read()
