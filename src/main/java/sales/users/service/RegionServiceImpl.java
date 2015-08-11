package sales.users.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import sales.users.domain.Country;
import sales.users.domain.Region;
import sales.users.repository.RegionRepository;

import java.util.List;

/**
 * Created by taras on 04.08.15.
 */
@Service("regionService")
public class RegionServiceImpl implements RegionService{
    final static Logger logger = LoggerFactory.getLogger(RegionServiceImpl.class);


    @Autowired
    private RegionRepository regionRepository;

    @Override
    public List<Region> getAll(Country country) {
        logger.debug("Get all regions");
        return regionRepository.findByCountry(country);
    }

    @Override
    public Region getOne(Country country, Long id) {
        logger.debug("Get region by id");
        return regionRepository.findByCountryAndId(country, id);
    }

    @Override
    public Region getOneByName(String name) {
        logger.debug("Get region by name");
        return regionRepository.findByName(name);
    }
}
