-- Severity Distribution: What is the count of vulnerabilities for different severity levels
select 
    count(*),
	bs.BASE_SEVERITY  
from 
    dw.vulnerabilities v 
join 
    dwtransform.base_severity bs on bs.RECORD_ID  = v.BASE_SEVERITY_ID
group by 
    bs.BASE_SEVERITY

--Worst Products, Platforms : Find out the worst products, platforms with most number of known vulnerabilities
select
    pl.platform,
    P.PRODUCT,
    COUNT(CVE_ID) AS vulnerability_count
FROM 
    dw.vulnerabilities v
inner join 
    dwtransform.product p on v.PRODUCT_ID = p.record_id
inner join 
    dwtransform.platform pl on v.PRODUCT_ID = pl.record_id
GROUP BY 
    p.product,pl.platform
ORDER BY 
    vulnerability_count DESC
LIMIT 100;

--List top 10 vulnerabilities that have the highest impact
SELECT 
    CVE_ID,
    DESCRIPTION_EN,
    p.product,
    IMPACT_SCORE
FROM 
    dw.vulnerabilities v
inner join 
    dwtransform.product p on v.PRODUCT_ID = p.record_id
ORDER BY 
    IMPACT_SCORE DESC
LIMIT 10;

--List top 10 vulnerabilities that have the highest exploitability scores
SELECT 
    CVE_ID,
    DESCRIPTION_EN,
    p.product,
    EXPLOITABILITY_SCORE 
FROM 
    dw.vulnerabilities v
inner join 
    dwtransform.product p on v.PRODUCT_ID = p.record_id
ORDER BY 
    EXPLOITABILITY_SCORE DESC
LIMIT 10;

--List top 10 attack vectors used
SELECT 
    av.ACCESS_VECTOR AS AttackVector,
    COUNT(v.ACCESS_VECTOR_ID) AS Frequency
FROM 
    dw.vulnerabilities v
JOIN 
    dwtransform.access_vector av ON v.ACCESS_VECTOR_ID = av.RECORD_ID
GROUP BY 
    av.ACCESS_VECTOR
ORDER BY 
    Frequency DESC
LIMIT 10;
