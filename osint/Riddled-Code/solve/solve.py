#!/usr/bin/env python3
"""Riddled Code (SecLeaf CTF 2026, OSINT) - rebuild the flag from the recovered facts.

The OSINT part (building code from the Office Navi listing, rate sign from the
September 2022 Street View capture of Times Utsubohonmachi No. 8) cannot be
automated offline. Those facts are embedded below exactly as recorded in our
notes; this script only does the calendar classification and the arithmetic.
"""
import calendar

# --- facts recovered during the investigation -------------------------------
BUILDING_CODE = "01000144"          # Office Navi, River Rise Utsubo Honmachi Building
YEAR, MONTH = 2022, 9               # "this month of the Harvest Moon" = September 2022
VEHICLES = 2                        # "our two shadows" = the two luxury vehicles

DAY_RATE_PER_10MIN = 220            # 07:00-22:00, ordinary Mon-Sat, no maximum
DAY_MINUTES = 15 * 60               # 07:00 -> 22:00
SUN_HOL_DAY_MAX = 1210              # 07:00-22:00 daytime maximum, Sundays/holidays
NIGHT_MAX = 330                     # 22:00-07:00 nighttime maximum, every date

# Japanese national holidays in September 2022 (NAOJ 2022 calendar)
HOLIDAYS = {19: "Respect for the Aged Day", 23: "Autumnal Equinox Day"}

# --- classify the dates -----------------------------------------------------
days_in_month = calendar.monthrange(YEAR, MONTH)[1]
sundays = [d for d in range(1, days_in_month + 1)
           if calendar.weekday(YEAR, MONTH, d) == calendar.SUNDAY]
discounted = sorted(set(sundays) | set(HOLIDAYS))
ordinary = days_in_month - len(discounted)

print(f"[*] Days in {calendar.month_name[MONTH]} {YEAR}: {days_in_month}")
print(f"[*] Sundays: {sundays}")
for d, name in HOLIDAYS.items():
    print(f"[*] Holiday: {MONTH}/{d} {name} ({calendar.day_name[calendar.weekday(YEAR, MONTH, d)]})")
print(f"[*] Sunday/holiday dates: {len(discounted)}  ordinary dates: {ordinary}")

# --- per-vehicle cost -------------------------------------------------------
ordinary_day = (DAY_MINUTES // 10) * DAY_RATE_PER_10MIN       # 90 units x 220
ordinary_full = ordinary_day + NIGHT_MAX
discount_full = SUN_HOL_DAY_MAX + NIGHT_MAX
one_vehicle = ordinary * ordinary_full + len(discounted) * discount_full

print(f"[*] Ordinary daytime: {DAY_MINUTES // 10} x {DAY_RATE_PER_10MIN} = {ordinary_day}")
print(f"[*] Ordinary full day: {ordinary_day} + {NIGHT_MAX} = {ordinary_full}")
print(f"[*] Sunday/holiday full day: {SUN_HOL_DAY_MAX} + {NIGHT_MAX} = {discount_full}")
print(f"[*] One vehicle: {ordinary} x {ordinary_full} + {len(discounted)} x {discount_full} = {one_vehicle}")

# cross-check: split day and night totals instead
alt = ordinary * ordinary_day + len(discounted) * SUN_HOL_DAY_MAX + days_in_month * NIGHT_MAX
assert alt == one_vehicle, (alt, one_vehicle)

total = VEHICLES * one_vehicle
print(f"[*] Two vehicles: {VEHICLES} x {one_vehicle} = {total} yen")

print(f"[+] FLAG: CRY{{{BUILDING_CODE}_{total}}}")
