package sales.bucket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sales.bucket.domain.Bucket;
import sales.users.domain.User;

/**
 * Created by taras on 13.08.15.
 */
public interface BucketRepository extends JpaRepository<Bucket, Long> {
    Bucket findByClient(User client);
}
