package sales.bucket.service;

import sales.bucket.domain.GoodInBucket;

import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
public interface GoodInBucketService {

    List<GoodInBucket> getAll(Long bucketId);

    GoodInBucket getOne(Long bucketId , Long goodId);

    GoodInBucket save(Long clientId, Long goodId, int price, int quantity, Long shopId);

    GoodInBucket save(GoodInBucket goodInBucket);

    void delete(Long goodId);
}
