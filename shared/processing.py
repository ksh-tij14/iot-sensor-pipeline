"""The computation edge and cloud both run on each chunk: a thermal-comfort
assessment from temperature and humidity.

Both services import this same function, so for the same chunk they must
produce the same result; validation treats a difference as a faulty or
tampered node. It works per chunk (no history), so results can be compared
chunk by chunk via chunk_id.
"""

import math

# US National Weather Service heat-index bands, in deg C.
COMFORT_BANDS = [
    (27.0, "comfortable"),
    (32.0, "caution"),
    (41.0, "extreme_caution"),
    (54.0, "danger"),
]


def heat_index_c(temp_c: float, humidity_pct: float) -> float:
    """'Feels like' temperature, NWS algorithm (Steadman, then Rothfusz
    regression with adjustments when it's hot enough for that to apply)."""
    t = temp_c * 9 / 5 + 32  # the formulas are defined in deg F
    rh = humidity_pct
    hi = 0.5 * (t + 61.0 + (t - 68.0) * 1.2 + rh * 0.094)
    if (hi + t) / 2 >= 80:
        hi = (-42.379 + 2.04901523 * t + 10.14333127 * rh - 0.22475541 * t * rh
              - 0.00683783 * t * t - 0.05481717 * rh * rh + 0.00122874 * t * t * rh
              + 0.00085282 * t * rh * rh - 0.00000199 * t * t * rh * rh)
        if rh < 13 and 80 <= t <= 112:
            hi -= ((13 - rh) / 4) * math.sqrt((17 - abs(t - 95)) / 17)
        elif rh > 85 and 80 <= t <= 87:
            hi += ((rh - 85) / 10) * ((87 - t) / 5)
    return (hi - 32) * 5 / 9


def dew_point_c(temp_c: float, humidity_pct: float) -> float:
    """Magnus formula."""
    a, b = 17.62, 243.12
    gamma = math.log(max(humidity_pct, 0.01) / 100) + a * temp_c / (b + temp_c)
    return b * gamma / (a - gamma)


def comfort_level(hi_c: float) -> str:
    for upper, label in COMFORT_BANDS:
        if hi_c < upper:
            return label
    return "extreme_danger"


def assess_comfort(data: dict) -> dict:
    """data uses the firmware's integer units (hundredths)."""
    temp_c = data["temp_centi_c"] / 100
    humidity_pct = data["humidity_centi_pct"] / 100
    hi = heat_index_c(temp_c, humidity_pct)
    return {
        "temp_c": round(temp_c, 2),
        "humidity_pct": round(humidity_pct, 2),
        "heat_index_c": round(hi, 2),
        "dew_point_c": round(dew_point_c(temp_c, humidity_pct), 2),
        "comfort": comfort_level(hi),
    }
