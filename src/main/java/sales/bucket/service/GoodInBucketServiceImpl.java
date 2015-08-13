package sales.bucket.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import sales.bucket.domain.Bucket;
import sales.bucket.domain.GoodInBucket;
import sales.bucket.repository.GoodInBucketRepository;
import sales.goods.domain.Good;
import sales.goods.service.GoodsService;
import sales.users.domain.User;
import sales.users.service.UserService;

import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
@Service("goodInBucketService")
public class GoodInBucketServiceImpl implements GoodInBucketService {

    @Autowired
    GoodInBucketRepository goodInBucketRepository;

    @Autowired
    BucketService bucketService;

    @Autowired
    UserService userService;

    @Autowired
    @Qualifier("goodsService")
    GoodsService goodsService;

    @Override
    public List<GoodInBucket> getAll(Long bucketId) {
        Bucket bucket = bucketService.getOne(bucketId);
        return goodInBucketRepository.findByBucket(bucket);
    }

    @Override
    public GoodInBucket getOne(Long bucketId, Long id) {
        Bucket bucket = bucketService.getOne(bucketId);
        return goodInBucketRepository.findByBucketAndId(bucket, id);
    }

    @Override
    public GoodInBucket save(Long clientId, Long goodId, int price, int quantity,  Long shopId) {
        Bucket bucket = bucketService.getOneByClientId(clientId);
        Good good = goodsService.get(goodId);
        User shop = userService.getShop(shopId);
        GoodInBucket goodInBucket = new GoodInBucket(bucket, good, price, quantity, shop);
        return goodInBucketRepository.save(goodInBucket);
    }

    @Override
    public GoodInBucket save(GoodInBucket goodInBucket) {
        return goodInBucketRepository.save(goodInBucket);
    }

    @Override
    public void delete(Long goodId) {
        goodInBucketRepository.delete(goodId);
    }
}
