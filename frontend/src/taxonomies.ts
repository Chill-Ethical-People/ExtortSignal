const COUNTRY_CODES = `AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`.split(" ");

const DISPLAY_OVERRIDES: Record<string, string> = {
  HK: "Hong Kong",
  MO: "Macao",
  TW: "Taiwan",
  GB: "United Kingdom",
  US: "United States",
  KR: "South Korea",
  KP: "North Korea",
  RU: "Russia",
  VN: "Vietnam",
  BO: "Bolivia",
  VE: "Venezuela",
  TZ: "Tanzania"
};

const names = new Intl.DisplayNames(["en"], { type: "region" });

export const COUNTRY_OPTIONS = COUNTRY_CODES.map((code) => ({
  code,
  name: DISPLAY_OVERRIDES[code] || names.of(code) || code
})).sort((left, right) => left.name.localeCompare(right.name));

export const HONG_KONG_REGION_OPTIONS = [
  "Hong Kong Island",
  "Kowloon",
  "New Territories",
  "Central and Western District, Hong Kong",
  "Eastern District, Hong Kong",
  "Southern District, Hong Kong",
  "Wan Chai District, Hong Kong",
  "Kowloon City District, Hong Kong",
  "Kwun Tong District, Hong Kong",
  "Sham Shui Po District, Hong Kong",
  "Wong Tai Sin District, Hong Kong",
  "Yau Tsim Mong District, Hong Kong",
  "Islands District, Hong Kong",
  "Kwai Tsing District, Hong Kong",
  "North District, Hong Kong",
  "Sai Kung District, Hong Kong",
  "Sha Tin District, Hong Kong",
  "Tai Po District, Hong Kong",
  "Tsuen Wan District, Hong Kong",
  "Tuen Mun District, Hong Kong",
  "Yuen Long District, Hong Kong"
] as const;

export const SINGAPORE_REGION_OPTIONS = [
  "Central Region, Singapore",
  "East Region, Singapore",
  "North Region, Singapore",
  "North-East Region, Singapore",
  "West Region, Singapore",
  "Ang Mo Kio, Singapore", "Bedok, Singapore", "Bishan, Singapore",
  "Boon Lay, Singapore", "Bukit Batok, Singapore", "Bukit Merah, Singapore",
  "Bukit Panjang, Singapore", "Bukit Timah, Singapore", "Central Water Catchment, Singapore",
  "Changi, Singapore", "Changi Bay, Singapore", "Choa Chu Kang, Singapore",
  "Clementi, Singapore", "Downtown Core, Singapore", "Geylang, Singapore",
  "Hougang, Singapore", "Jurong East, Singapore", "Jurong West, Singapore",
  "Kallang, Singapore", "Lim Chu Kang, Singapore", "Mandai, Singapore",
  "Marina East, Singapore", "Marina South, Singapore", "Marine Parade, Singapore",
  "Museum, Singapore", "Newton, Singapore", "North-Eastern Islands, Singapore",
  "Novena, Singapore", "Orchard, Singapore", "Outram, Singapore",
  "Pasir Ris, Singapore", "Paya Lebar, Singapore", "Pioneer, Singapore",
  "Punggol, Singapore", "Queenstown, Singapore", "River Valley, Singapore",
  "Rochor, Singapore", "Seletar, Singapore", "Sembawang, Singapore",
  "Sengkang, Singapore", "Serangoon, Singapore", "Simpang, Singapore",
  "Singapore River, Singapore", "Southern Islands, Singapore", "Straits View, Singapore",
  "Sungei Kadut, Singapore", "Tampines, Singapore", "Tanglin, Singapore",
  "Tengah, Singapore", "Toa Payoh, Singapore", "Tuas, Singapore",
  "Western Islands, Singapore", "Western Water Catchment, Singapore",
  "Woodlands, Singapore", "Yishun, Singapore"
] as const;

export const GEOGRAPHY_OPTIONS = [
  ...COUNTRY_OPTIONS.map((country) => country.name),
  ...HONG_KONG_REGION_OPTIONS,
  ...SINGAPORE_REGION_OPTIONS
].filter((value, index, values) => values.indexOf(value) === index)
  .sort((left, right) => left.localeCompare(right));

export const INDUSTRY_OPTIONS = [
  "Aerospace and defense",
  "Agriculture",
  "Automotive",
  "Business services",
  "Construction",
  "Consumer services",
  "Critical Infrastructure",
  "Education",
  "Energy",
  "Financial services",
  "Food and beverage",
  "Government and public sector",
  "Healthcare",
  "Hospitality and tourism",
  "Insurance",
  "Legal services",
  "Manufacturing",
  "Media and entertainment",
  "Mining and materials",
  "Nonprofit",
  "Pharmaceuticals and biotechnology",
  "Professional services",
  "Real estate",
  "Retail and e-commerce",
  "Technology",
  "Telecommunications",
  "Transportation and logistics",
  "Utilities",
  "Other"
] as const;
