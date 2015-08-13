package sales.bucket.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import sales.bucket.domain.Bucket;
import sales.bucket.domain.GoodInBucket;
import sales.bucket.service.BucketService;
import sales.bucket.service.GoodInBucketService;
import sales.users.domain.User;

import java.io.IOException;
import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
@RestController
@RequestMapping(value = "/bucket")
public class BucketController {
    final static Logger logger = LoggerFactory.getLogger(BucketController.class);

    @Autowired
    BucketService bucketService;

    @Autowired
    GoodInBucketService goodInBucketService;

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/{clientId}",
            produces = "application/json")
    public Bucket getBucketByClientId(@PathVariable("clientId") Long clientId) {
        logger.info("get all buckets");
        return bucketService.getOneByClientId(clientId);
    }

    @RequestMapping(
            method = RequestMethod.DELETE,
            value = "/{clientId}/{id}",
            produces = "application/json")
    @ResponseStatus(HttpStatus.OK)
    public void deleteGoodFromBucket(@PathVariable("id") Long goodId) {
        logger.info("Delete good from bucket");
        goodInBucketService.delete(goodId);
    }

    @RequestMapping(value = "/{clientId}",
            method = RequestMethod.POST,
            produces = "application/json; charset=UTF-8",
            consumes = "application/json")
    @ResponseStatus(HttpStatus.CREATED)
    public GoodInBucket putGoods(@RequestBody GoodInBucket goodInBucket) throws IOException {
        logger.info("Good: save or update using hibernate");
        return goodInBucketService.save(goodInBucket);
    }
}
