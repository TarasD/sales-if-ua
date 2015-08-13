package sales.bucket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sales.bucket.domain.Bucket;
import sales.bucket.domain.GoodInBucket;

import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
public interface GoodInBucketRepository extends JpaRepository<GoodInBucket, Long> {
    List<GoodInBucket> findByBucket(Bucket bucket);

    GoodInBucket findByBucketAndId(Bucket bucket, Long id);
}
